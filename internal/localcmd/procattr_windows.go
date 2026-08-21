//go:build windows

package localcmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// killWait is how long taskkill is given before Joro gives up on it and kills the direct
// child instead. Generous for a local process-tree walk, and bounded so a cancelled run
// cannot be held open by a hung killer.
const killWait = 5 * time.Second

// CapInlineInputBytes is the most {{INPUT}} may put into argv on this platform.
//
// Windows bounds the whole command line rather than one argument: CreateProcess refuses
// past 32767 characters, and cmd.exe — which runs any .bat or .cmd target — refuses past
// 8191. This sits under the lower figure with room for the program path and the rest of
// the arguments, so the budget refuses first and says why, rather than the run failing to
// spawn with an error that names nothing.
//
// Counted in bytes against a limit in UTF-16 characters, which is conservative in the only
// direction that matters: a non-ASCII rune costs more bytes here than characters there.
const CapInlineInputBytes = 6 << 10

// procAttr has nothing to set here beyond what applyCmdLine adds.
//
// Windows has a real equivalent of a process group — a job object — but os/exec offers no
// way to reach one without owning the CreateProcess flags and the handle, so the tree is
// taken down by taskkill instead; see killTree.
func procAttr() *syscall.SysProcAttr { return nil }

// applyCmdLine replaces the command line Go would have built, when the target is one
// cmd.exe parses rather than one following the ordinary argv rules.
//
// This is the whole Windows half of the fix in cmdline.go. It runs after Path has been
// resolved, so the extension it keys on is the one that will actually execute. Setting
// CmdLine leaves the executable alone: CreateProcess is given Path separately, so this
// changes what the program is told and never which program it is.
//
// An argument that cannot be represented for cmd.exe stops the run rather than being
// silently mangled — the caller reports it as a refusal, with the reason.
func applyCmdLine(cmd *exec.Cmd) error {
	if !needsCmdEscaping(cmd.Path) {
		// Go's own escaping is correct for everything else, and overriding it here would
		// be a regression rather than a fix.
		return nil
	}
	line, err := cmdCommandLine(cmd.Path, cmd.Args[1:])
	if err != nil {
		return err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CmdLine = line
	return nil
}

// killTree terminates the command and everything it spawned.
//
// os/exec's own cancellation kills the named process only, and the programs worth running
// here spawn others — a wrapper invoking the real binary, a tool forking workers. Killing
// the parent alone leaves those running against a target after Joro has reported the run
// stopped, which is the failure worth avoiding.
//
// taskkill is the platform's own answer and needs no handle plumbing: /T walks the tree
// from the given pid, /F does not ask. Resolved from %SystemRoot%\System32 rather than
// through PATH deliberately — PATHEXT would happily accept a taskkill.cmd planted earlier
// on PATH, which is the very hazard the rest of this file exists to close.
//
// Everything about the invocation is fixed: a constant argv and a numeric pid, with nothing
// derived from a captured request. On failure it falls back to killing the direct child,
// which is exactly what this platform did before.
func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid

	// Its own context: the run's is already cancelled by the time this is called, so
	// deriving from it would abort the killer immediately.
	ctx, cancel := context.WithTimeout(context.Background(), killWait)
	defer cancel()

	kill := exec.CommandContext(ctx, taskkillPath(), "/T", "/F", "/PID", strconv.Itoa(pid))
	if err := kill.Run(); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}

// taskkillPath returns the absolute path to taskkill, falling back to the bare name only
// when the system root is not in the environment — at which point PATH is all there is.
func taskkillPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("SYSTEMROOT")
	}
	if root == "" {
		return "taskkill.exe"
	}
	return filepath.Join(root, "System32", "taskkill.exe")
}
