package localcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// waitDelay bounds cleanup after the process exits or the context is done.
//
// os/exec copies a non-file stdin through a goroutine, so a command that exits without
// reading what it was piped leaves that copy blocked on a closed pipe. Without a delay
// Wait would block on it forever; with one, the pipes are closed and Wait returns. The
// same delay covers a command that leaves a grandchild holding its stdout.
const waitDelay = 2 * time.Second

// RunOpts is everything about one run that is not the spec itself.
type RunOpts struct {
	// Limits is the resolved budget. Fill is applied here, not NormalizeWith: by the
	// time a caller reaches this package the operator's policy has already been
	// applied, and re-normalizing would silently lower a limit they raised.
	Limits Limits

	// Scratch is the run's working directory. The caller creates it 0700 and owns its
	// lifetime; this package sets it as the process's Dir, writes materialized inputs
	// into it, and collects what the command left behind.
	//
	// Required. A command with no scratch directory would inherit Joro's own working
	// directory, which is wherever the operator started the binary — so a scanner
	// writing a report directory would write it into their source tree.
	Scratch string

	// Inputs names the files this package wrote into Scratch before the command
	// started, so they are not reported back as things the command produced.
	Inputs []string

	// Subst resolves the {{PLACEHOLDER}} references in Spec.Args.
	Subst Substitutions

	// ProxyURL and CAFile are used only when Spec.UseProxy is set. ProxyURL is a full
	// URL ("http://127.0.0.1:8080"); CAFile is a path to Joro's CA certificate in PEM
	// form, so a tool that honours the conventional variables can verify Joro's
	// interception instead of failing the handshake.
	ProxyURL string
	CAFile   string
}

// Run executes one command and returns what happened.
//
// The returned error means the run could not be attempted at all — no scratch
// directory, a spec this package cannot make sense of. Everything else, including a
// command that never started, timed out, was killed or exited non-zero, comes back as a
// Result carrying its reason. A caller therefore has one thing to report and one place
// to look, which is the contract jsautomation.Manager.Run already relies on.
func Run(ctx context.Context, s Spec, stdin io.Reader, opts RunOpts) (Result, error) {
	if opts.Scratch == "" {
		return Result{}, errors.New("localcmd: a run needs a scratch directory")
	}
	lim := opts.Limits.Fill()
	start := time.Now()

	// Every return below goes through this, so the budget the run was held to and its
	// duration are stamped once rather than at each exit. Same reason vm.go funnels
	// its returns through finish: on a failure these are most of what explains it, and
	// repeating them at each return is how one gets forgotten.
	done := func(r Result) (Result, error) {
		r.Outcome = OutcomeFor(r.Reason)
		r.Limits = lim.Budget()
		r.DurationMs = time.Since(start).Milliseconds()
		if r.Artifacts == nil {
			r.Artifacts = collect(opts.Scratch, opts.Inputs, lim.MaxArtifactBytes)
		}
		return r, nil
	}

	args, err := substitute(s.Args, opts.Subst, lim.MaxInlineInputBytes)
	if err != nil {
		// Refused before spawning. The message names the argument and the rule, which
		// is the whole value of refusing here rather than passing a suspicious value
		// through and letting the tool misread it.
		//
		// Inline input over budget gets its own reason: the fix is a larger budget or
		// stdin, neither of which an operator reading "not permitted" would look for.
		reason := ReasonNotPermitted
		if errors.Is(err, ErrInlineTooLarge) {
			reason = ReasonInputTooLarge
		}
		return done(Result{Reason: reason, Err: err.Error(), ExitCode: -1})
	}

	runCtx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	// overflow records that an output cap was hit. It has to be separate from the
	// context error because hitting a cap cancels the run, and a cancelled context
	// would otherwise be reported as a timeout — two very different things for an
	// operator to read.
	var overflow atomic.Bool

	outBuf := &capBuffer{max: lim.MaxStdoutBytes, onFull: func() {
		overflow.Store(true)
		cancel()
	}}
	errBuf := &capBuffer{max: lim.MaxStderrBytes}

	cmd := exec.CommandContext(runCtx, s.Path, args...)
	cmd.Dir = opts.Scratch
	cmd.Env = buildEnv(s, opts)
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	cmd.WaitDelay = waitDelay
	cmd.SysProcAttr = procAttr()

	// The default Cancel kills only the direct child. A program that spawns workers would
	// leave them running with the pipes open, so the whole tree goes at once. See killTree
	// for how that is done per platform.
	cmd.Cancel = func() error { return killTree(cmd) }

	// On Windows, rebuild the command line when the resolved target is one cmd.exe parses
	// rather than one following the ordinary argv rules — a .bat or .cmd, which PATHEXT
	// will resolve a bare program name onto. Without this, cmd.exe's own metacharacters
	// survive in an argument, and an argument may hold a captured URL. cmdline.go carries
	// the whole argument; this is a no-op everywhere else.
	if err := applyCmdLine(cmd); err != nil {
		return done(Result{
			Reason:   ReasonNotPermitted,
			Err:      err.Error(),
			ExitCode: -1,
		})
	}

	if s.Stdin != StdinNone && stdin != nil {
		// The delivery with no limits attached: unbounded, binary-safe, and invisible to
		// other processes on the host, where argv is readable through /proc and ps. The
		// spec can also ask for these bytes inline in an argument, which is bounded on
		// all three counts — the package header sets out the trade and substitute
		// enforces it. Neither affects the injection boundary, which is a property of
		// argv being a list.
		cmd.Stdin = stdin
	}

	if err := cmd.Start(); err != nil {
		return done(Result{
			Reason:   ReasonSpawnFailed,
			Err:      spawnDetail(s.Path, err),
			ExitCode: -1,
		})
	}

	waitErr := cmd.Wait()

	res := Result{
		Stdout:          outBuf.Bytes(),
		Stderr:          errBuf.Bytes(),
		StdoutTruncated: outBuf.Truncated(),
		StderrTruncated: errBuf.Truncated(),
		ExitCode:        exitCodeOf(cmd),
	}

	switch {
	case overflow.Load():
		res.Reason = ReasonOutputLimit
		res.Err = fmt.Sprintf("the command produced more than its %d KB output budget and was stopped. "+
			"What it wrote up to that point is below; raise the budget or narrow what the command prints.",
			lim.MaxStdoutBytes>>10)

	case ctx.Err() != nil:
		res.Reason = ReasonCancelled
		res.Err = "the run was cancelled"

	case runCtx.Err() != nil:
		res.Reason = ReasonTimeout
		res.Err = fmt.Sprintf("the command exceeded its %s limit and was stopped, along with "+
			"anything it had started", lim.Timeout)

	case res.ExitCode != 0:
		// Not an error in Joro. A search program exits non-zero when it matches
		// nothing, and a scanner may exit non-zero when it finds something; the code is
		// reported and the operator decides what it meant.
		res.Reason = ReasonExitStatus
		if res.ExitCode < 0 {
			res.Err = waitDetail(waitErr)
		}

	default:
		res.Reason = ReasonSuccess
	}
	return done(res)
}

// exitCodeOf reads the process's status, or -1 when it never reported one.
func exitCodeOf(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.ExitCode()
}

// spawnDetail explains a failure to start in terms the operator can act on. The two
// realistic causes need different fixes and the raw syscall error names neither.
func spawnDetail(path string, err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Sprintf("%s does not exist. It resolved when this automation was installed, so the "+
			"tool has been moved or uninstalled since.", path)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Sprintf("%s is not executable by this user.", path)
	default:
		return fmt.Sprintf("%s could not be started: %v", path, err)
	}
}

// waitDetail explains a process that produced no exit status. Reached only when the
// process was signalled or the wait itself failed, both of which are worth naming
// rather than reporting as exit code -1.
func waitDetail(err error) string {
	if err == nil {
		return "the command exited without reporting a status"
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return "the command exited but left its output pipes open, and they were closed underneath it. " +
			"Any output it had not flushed is lost."
	}
	return fmt.Sprintf("the command did not report an exit status: %v", err)
}

// capBuffer collects output up to a ceiling.
//
// os/exec writes to it from its own goroutine while the caller reads it after Wait, so
// the lock is not decorative — the same reason jsruntime's worker guards its stderr
// buffer.
//
// onFull fires exactly once, on the write that first crosses the ceiling. Firing on
// every subsequent write would cancel a context that is already cancelled, harmlessly
// but pointlessly; firing once means the callback can be something with a cost.
type capBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	max    int
	full   bool
	onFull func()
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	notify := false
	if !c.full {
		room := c.max - c.buf.Len()
		if room > 0 {
			n := min(room, len(p))
			c.buf.Write(p[:n])
		}
		if c.buf.Len() >= c.max {
			c.full = true
			notify = c.onFull != nil
		}
	}
	c.mu.Unlock()

	// Outside the lock: the callback cancels a context, which can wake goroutines that
	// go on to write here again, and holding the mutex across that is a deadlock.
	if notify {
		c.onFull()
	}
	// Always report the full length written. Returning short would make os/exec report
	// a short-write error on top of the limit Joro is already reporting.
	return len(p), nil
}

func (c *capBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes())
}

func (c *capBuffer) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.full
}

// baseEnvNames are the variables inherited from Joro's environment when present.
//
// A whitelist, and a short one. PATH is here because Spec.Path is already absolute but
// a program often is not a leaf — it may invoke an interpreter or a helper of its own —
// and one with no PATH fails in a way that looks like a Joro bug. The Windows entries
// are not optional there: a process without SYSTEMROOT cannot load a system DLL.
//
// Everything else in the operator's environment stays out. A pentester's shell exports
// cloud credentials, API tokens and registry passwords, and none of that belongs in the
// environment of a tool an automation fires on captured traffic.
var baseEnvNames = []string{
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"LANG",
	"LC_ALL",
	"TZ",

	// Windows.
	"SYSTEMROOT",
	"WINDIR",
	"COMSPEC",
	"PATHEXT",
	"SYSTEMDRIVE",
	"USERPROFILE",
	"LOCALAPPDATA",
	"APPDATA",
	"PROGRAMDATA",
	"PROGRAMFILES",
	"NUMBER_OF_PROCESSORS",
	"PROCESSOR_ARCHITECTURE",
}

// proxyEnvNames are the conventional proxy variables, set when Spec.UseProxy is on.
// Both cases: libcurl reads the lowercase names, most Go and Python tooling reads the
// uppercase ones, and a tool that reads only one of the two is common enough that
// setting one would look like the feature not working.
var proxyEnvNames = []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"}

// caEnvNames are the CA-bundle variables pointed at Joro's own certificate, so a tool
// routed through the proxy can verify the leaf Joro mints instead of failing the
// handshake. Each belongs to a different ecosystem and none is a superset of another.
var caEnvNames = []string{
	"SSL_CERT_FILE",       // OpenSSL, and Go's fallback on Unix
	"CURL_CA_BUNDLE",      // curl
	"REQUESTS_CA_BUNDLE",  // python-requests
	"NODE_EXTRA_CA_CERTS", // Node
	"GIT_SSL_CAINFO",      // git
}

// buildEnv assembles the command's environment from nothing, in four layers: the base
// whitelist, the scratch redirection, the proxy and CA variables, then the operator's
// own — so a spec can override anything Joro set, which is the right precedence for a
// value they typed deliberately.
func buildEnv(s Spec, opts RunOpts) []string {
	env := make(map[string]string, len(baseEnvNames)+len(s.Env)+12)

	for _, name := range baseEnvNames {
		if v, ok := os.LookupEnv(name); ok {
			env[name] = v
		}
	}

	// Point the temporary directory at the run's own scratch. A tool's temp files then
	// live and die with the run instead of accumulating in the operator's /tmp, and
	// anything it meant to keep shows up as an artifact.
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		env[name] = opts.Scratch
	}

	if s.UseProxy {
		if opts.ProxyURL != "" {
			for _, name := range proxyEnvNames {
				env[name] = opts.ProxyURL
			}
		}
		if opts.CAFile != "" {
			for _, name := range caEnvNames {
				env[name] = opts.CAFile
			}
		}
	}

	for _, name := range s.EnvPass {
		if v, ok := os.LookupEnv(name); ok {
			env[name] = v
		}
	}
	maps.Copy(env, s.Env)

	out := make([]string, 0, len(env))
	for name, v := range env {
		out = append(out, name+"="+v)
	}
	// Sorted so two runs of the same spec produce a byte-identical environment, which
	// makes a difference in behavior between them something other than ordering.
	sort.Strings(out)
	return out
}

// resolveExecutable turns a spec's Path into an absolute path to a runnable file.
//
// Resolution happens once, at install time, and the result is what gets stored. A bare
// name looked up again at run time would resolve against whatever PATH Joro inherited
// from the shell that started it — so a tool placed earlier on that PATH than the one
// the operator reviewed would run instead, and nothing in the UI would show a
// difference. Storing the absolute path is what makes "the binary you reviewed" true.
func resolveExecutable(path string) (string, error) {
	if strings.ContainsAny(path, `/\`) || strings.HasPrefix(path, ".") {
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("command.path %q could not be resolved: %w", path, err)
		}
		info, err := os.Stat(abs)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", fmt.Errorf("command.path %q does not exist", abs)
		case err != nil:
			return "", fmt.Errorf("command.path %q could not be read: %w", abs, err)
		case info.IsDir():
			return "", fmt.Errorf("command.path %q is a directory", abs)
		}
		return abs, nil
	}

	found, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("command.path %q was not found on PATH. Give an absolute path, or install "+
			"the tool where Joro can see it — Joro resolves this once, now, so that the binary you "+
			"review is the one that runs", path)
	}
	abs, err := filepath.Abs(found)
	if err != nil {
		return "", fmt.Errorf("command.path %q resolved to %q, which could not be made absolute: %w",
			path, found, err)
	}
	return abs, nil
}

// collect reports what the command left in its scratch directory, and enforces the
// artifact budget by deleting what does not fit.
//
// Sorted by name and truncated from the end rather than by size, so which files survive
// is predictable from the listing rather than from how large each happened to be. A file
// past the budget is still *reported*, marked dropped — a scanner whose report directory
// did not fit should say so, not appear to have written nothing.
//
// Best effort throughout: a walk that fails reports what it managed, because a run that
// worked must not be reported as failed by an artifact listing that did not.
func collect(scratch string, inputs []string, budget int64) []Artifact {
	skip := make(map[string]struct{}, len(inputs))
	for _, name := range inputs {
		skip[filepath.ToSlash(name)] = struct{}{}
	}

	type found struct {
		name string
		size int64
	}
	var all []found

	_ = filepath.WalkDir(scratch, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			// A directory Joro cannot read is skipped rather than failing the walk.
			return nil //nolint:nilerr // best effort by design
		}
		rel, rerr := filepath.Rel(scratch, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if _, ok := skip[rel]; ok {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		all = append(all, found{name: rel, size: info.Size()})
		return nil
	})

	if len(all) == 0 {
		return nil
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })

	out := make([]Artifact, 0, len(all))
	var used int64
	for _, f := range all {
		a := Artifact{Name: f.name, Bytes: f.size}
		if budget > 0 && used+f.size > budget {
			a.Dropped = true
			_ = os.Remove(filepath.Join(scratch, filepath.FromSlash(f.name)))
		} else {
			used += f.size
		}
		out = append(out, a)
	}
	return out
}
