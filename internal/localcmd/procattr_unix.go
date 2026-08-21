//go:build unix

package localcmd

import (
	"os/exec"
	"syscall"
	"time"
)

// killGrace is how long the process group has between SIGTERM and SIGKILL. Long enough
// for a tool to flush partial output and short enough that a cancelled run is over
// quickly; os/exec's WaitDelay closes the pipes regardless, so nothing waits on this.
const killGrace = 3 * time.Second

// CapInlineInputBytes is the most {{INPUT}} may put into argv on this platform.
//
// Linux refuses a single argument over MAX_ARG_STRLEN, which is 32 pages — 128 KiB — and
// returns E2BIG from exec with nothing to say about which argument was at fault. macOS
// applies ARG_MAX to the whole block instead, at 1 MiB. This sits under the lower of the
// two with room for the rest of the command line, so the budget refuses first and names
// the fix rather than letting the kernel report a spawn failure.
const CapInlineInputBytes = 96 << 10

// procAttr puts the command in its own process group.
//
// This is what makes killTree able to reach the whole tree. Setsid is deliberately not
// used: a new session would also detach the process from Joro's controlling terminal,
// and a tool that notices it has no tty sometimes changes behaviour — dropping colour is
// harmless, but prompting differently or refusing to run is not. A process group is
// enough to signal, and nothing here needs a session.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// applyCmdLine has nothing to do here: the command line is only rebuilt for the targets
// Windows parses through cmd.exe. See cmdline.go.
func applyCmdLine(*exec.Cmd) error { return nil }

// killTree signals the command's whole process group.
//
// The default os/exec cancellation kills the direct child only, and a program often spawns
// others — a wrapper invoking the real binary, a tool forking workers. Those children
// inherit the group but not the parent's death. Killing the child alone leaves them running
// with the output pipes open, so Joro's own Wait would block on the pipes for WaitDelay and
// the operator would be left with orphaned processes still reaching their target after the
// run had been reported as stopped.
//
// SIGTERM first so a tool can flush partial output and clean up, then SIGKILL after a
// grace period for anything that ignores it. The negative pid is the group.
func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	pgid := -cmd.Process.Pid

	if err := syscall.Kill(pgid, syscall.SIGTERM); err != nil {
		// The group is already gone, or was never created because the exec failed
		// between fork and the setpgid taking effect. Fall back to the process itself
		// rather than reporting a failure the caller cannot act on.
		return cmd.Process.Kill()
	}

	// Escalate from a separate goroutine so cancellation is not held up by the grace
	// period. os/exec's WaitDelay is the backstop that closes the pipes regardless, so
	// this only has to be best effort.
	go func() {
		time.Sleep(killGrace)
		_ = syscall.Kill(pgid, syscall.SIGKILL)
	}()
	return nil
}
