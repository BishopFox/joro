// Package localcmd runs one local operating-system command under hard limits.
//
// It is a leaf package: it imports nothing from the rest of Joro, the same shape
// internal/jsruntime has and for the same reason. Everything a command may see arrives
// through a Spec and a Substitutions, so there is no field on any type here through
// which a command could reach a capture store, a token file, or an HTTP client.
//
// # Not internal/shell
//
// internal/shell also holds a command "executor". That one runs commands on a *remote*
// target through a web shell Joro deployed, over HTTP, with the scope guard applied to
// the target URL. This package runs a command on the operator's *own machine*. The two
// are unrelated and the names are close enough to confuse, which is why this one says
// "local" in it.
//
// # What this contains, and what it does not
//
// A command is not sandboxed. It is a process running as the operator with the
// operator's filesystem and network, and nothing here changes that — Joro's own threat
// model already says as much: any process running as the operator can drive the whole
// API. What this package contains is the realistic failure. A command cannot run
// forever, cannot fill memory, cannot return unbounded output, cannot write into the
// operator's working directory, and cannot be steered by the bytes it is fed.
//
// That last one is the part that takes work, and it is what most of this file is.
//
// # The argv rule, precisely
//
// The property that matters is not "captured bytes never reach argv". It is this:
//
//	The number of argv elements, their boundaries, and the identity of the program are
//	fixed before any wire-derived byte is known. At run time a value can only be
//	interpolated *into* an element that already exists.
//
// That is what the list form of Spec.Args buys, and it is what closes the injection class
// captured traffic makes live: substitute runs over an array that already exists, so a
// value holding a space, a quote, a semicolon or a newline still lands in exactly one
// element and cannot split, merge, create or reorder one, nor change which program runs.
//
// Given that property, bytes in argv are a question of cost rather than of safety, and the
// costs are bounded rather than avoided. A small value derived from the wire — a host, a
// URL, a status — is held to a grammar for its name. The transaction's own bytes reach a
// command on stdin, in a file, or — when the operator writes {{INPUT}} into an argument —
// inline in argv, where three things are true and are bounded accordingly:
//
//   - Length. A platform refuses an over-long argument at exec time (Linux caps one
//     argument at MAX_ARG_STRLEN, Windows the whole command line at 32767), so the inline
//     budget sits below that and refuses first, with a reason naming the alternative.
//   - Representability. argv is NUL-terminated, and Windows re-encodes it to UTF-16, so a
//     NUL is impossible and invalid UTF-8 corrupts. Both are refused.
//   - Confidentiality. argv is readable by other processes on this host, through
//     /proc/<pid>/cmdline and ps. Stdin is not. This one cannot be engineered away, so it
//     is stated where the operator chooses it rather than bounded here.
//
// See Substitutions, substitute and checkBulk.
//
// One thing argv validation does not cover on its own, because it is a property of the
// target rather than of the value: Windows runs a .bat or .cmd through cmd.exe, which
// parses the command line by different rules than the ones Go escapes for. cmdline.go
// closes that, and the two have to be read together — the guarantee that a captured URL is
// safe in argv rests on there being no shell in the path, on either platform.
//
// # The author-time tokenizer
//
// The editor offers a single command box rather than one input per argument, and
// web/src/lib/cmdline.ts is what splits that text into a program and an argument list. It
// runs in the browser, before storage, and its output is argv: the wire shape, the manifest
// on disk and every type here are unchanged, and no field anywhere takes a command line as
// one string. Tokenizing at author time is precisely what keeps the property above true —
// the split is applied to the template, never to a resolved value.
//
// # Permissions
//
// The scratch tree is created 0700 and its files 0600. Those are advisory on Windows, where
// Go maps a mode onto little more than the read-only bit; there the profile directory's own
// ACL is what keeps the tree private, as it already is for the rest of ~/.joro.
package localcmd

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Termination reasons. Every run ends with exactly one, and the operator sees it
// verbatim, so they are phrased as outcomes rather than error classes. Same two-field
// pattern as jsruntime: prose here, a stable code below.
const (
	ReasonSuccess = "success"
	// ReasonExitStatus means the command ran and exited non-zero. Not an error in
	// Joro — a search program exits non-zero when it matches nothing — so the exit code
	// is reported and the caller decides what it meant.
	ReasonExitStatus = "exit status"
	ReasonTimeout    = "timeout"
	ReasonCancelled  = "cancelled"
	// ReasonOutputLimit means the command produced more than its output budget and
	// was stopped. Distinct from a truncated success: output that hit the ceiling
	// mid-stream is not a complete answer, and reporting it as one would be worse
	// than saying so.
	ReasonOutputLimit = "output limit"
	// ReasonSpawnFailed means the process never started — a missing or unexecutable
	// binary, or a scratch directory that could not be made.
	ReasonSpawnFailed = "spawn failed"
	// ReasonNotPermitted means Joro refused before spawning: a placeholder that did
	// not validate, a disabled feature, an unresolvable spec.
	ReasonNotPermitted = "not permitted"
	// ReasonInputTooLarge means {{INPUT}} would have put more bytes into argv than the
	// inline budget allows, so the run was refused before spawning.
	//
	// Its own reason rather than a shade of ReasonNotPermitted, because the two send an
	// operator to different places: "not permitted" reads as a missing grant or a
	// disabled feature, where this one has two real fixes — raise the budget, or pipe
	// the input on stdin instead, which has no size limit at all.
	ReasonInputTooLarge = "input too large"
	// ReasonRuntimeFailure is ours, not the command's.
	ReasonRuntimeFailure = "runtime failure"
)

// Outcome codes pair one-to-one with the reasons above. A reason is prose the operator
// reads and is free to be reworded; an outcome is an identifier a program branches on
// and is therefore not.
const (
	OutcomeSuccess        = "success"
	OutcomeExitStatus     = "exit_status"
	OutcomeTimeout        = "timeout"
	OutcomeCancelled      = "cancelled"
	OutcomeOutputLimit    = "output_limit"
	OutcomeSpawnFailed    = "spawn_failed"
	OutcomeNotPermitted   = "not_permitted"
	OutcomeInputTooLarge  = "input_too_large"
	OutcomeRuntimeFailure = "runtime_failure"

	// OutcomeUnknown is what an unmapped reason resolves to, so the mapping fails
	// safe: a reason added without a code here reports a run whose fate is
	// unrecognized rather than a run that succeeded.
	OutcomeUnknown = "unknown"
)

// OutcomeFor returns the stable code for a termination reason.
func OutcomeFor(reason string) string {
	switch reason {
	case ReasonSuccess:
		return OutcomeSuccess
	case ReasonExitStatus:
		return OutcomeExitStatus
	case ReasonTimeout:
		return OutcomeTimeout
	case ReasonCancelled:
		return OutcomeCancelled
	case ReasonOutputLimit:
		return OutcomeOutputLimit
	case ReasonSpawnFailed:
		return OutcomeSpawnFailed
	case ReasonNotPermitted:
		return OutcomeNotPermitted
	case ReasonInputTooLarge:
		return OutcomeInputTooLarge
	case ReasonRuntimeFailure:
		return OutcomeRuntimeFailure
	default:
		return OutcomeUnknown
	}
}

// Stdin modes: what the command reads on its standard input.
const (
	StdinNone     = "none"
	StdinRequest  = "request"
	StdinResponse = "response"
	StdinBoth     = "both"
	// StdinTrigger feeds the trigger payload as JSON. It is what a detect.finding or
	// fuzzer.complete trigger has to offer: those carry no single transaction, so
	// there are no request bytes to pipe.
	StdinTrigger = "trigger"
)

// StdinModes lists the valid Spec.Stdin values, in the order the UI shows them.
var StdinModes = []string{StdinNone, StdinRequest, StdinResponse, StdinBoth, StdinTrigger}

// Output modes: how a lens tab should render stdout.
const (
	OutputText = "text"
	OutputJSON = "json"
)

// OutputModes lists the valid Spec.Output values.
var OutputModes = []string{OutputText, OutputJSON}

// Part names for Files, matching the Stdin vocabulary that overlaps with it.
const (
	PartRequest  = "request"
	PartResponse = "response"
	PartBoth     = "both"
	PartTrigger  = "trigger"
)

// FileParts lists what Files may materialize.
var FileParts = []string{PartRequest, PartResponse, PartBoth, PartTrigger}

// Shape limits on a spec. These bound what an operator can declare, not what a command
// can do; they exist so a hand-edited or generated manifest cannot produce an argv
// nobody can read or an environment nobody reviewed.
const (
	MaxPathLen  = 512
	MaxArgs     = 64
	MaxArgLen   = 4096
	MaxFiles    = 8
	MaxEnvVars  = 32
	MaxEnvName  = 128
	MaxEnvValue = 4096

	// maxSubstValue bounds one substituted placeholder. A URL from a captured
	// request is the realistic worst case and is nowhere near this.
	maxSubstValue = 4096
)

var (
	// placeholderPattern matches {{NAME}} in an argv element. Uppercase with
	// underscores only, so it cannot be confused for a shell or template syntax a
	// reader might expect Joro to honour — it honours nothing but this.
	placeholderPattern = regexp.MustCompile(`\{\{([A-Z][A-Z0-9_]*)\}\}`)

	// fileKeyPattern is the same shape, for the keys of Spec.Files. A key is the
	// placeholder that will resolve to the written file's path.
	fileKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

	// envNamePattern is the POSIX environment-variable name shape.
	envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Artifact is one file the command left in its scratch directory.
//
// Name is relative to the scratch root and is what a download route takes, so it is
// held to a shape that cannot escape that root even before the route re-validates it.
type Artifact struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`

	// Dropped means the file was past the run's artifact budget and has been deleted.
	// Still reported, because a scanner whose report directory did not fit should say
	// so rather than appear to have written nothing.
	Dropped bool `json:"dropped,omitempty"`
}

// Spec is what to run.
//
// Args is a list and there is no field that takes a command line as one string. That is
// the single most important property in this package, and the package header states it
// exactly: the shape of argv is fixed before any wire byte is known, so a value holding a
// semicolon, a backtick or a newline is one argument rather than the start of another.
// Adding a `shell` or `command` string field for convenience would reintroduce the whole
// injection class, and would look like a small ergonomic improvement while doing so — the
// editor's single command box is not that field, because it splits in the browser at
// author time and stores the result here as a list.
type Spec struct {
	// Path is the executable. Validate resolves it through exec.LookPath and rewrites
	// this field to the absolute result, so the binary the operator reviewed is the
	// binary that runs. A bare name looked up again at run time would be shadowable
	// from whatever directory Joro happened to be started in.
	Path string `json:"path"`

	// Args are the arguments, after {{PLACEHOLDER}} substitution. Placeholders resolve
	// only to values Joro computed or validated; see substitute.
	Args []string `json:"args,omitempty"`

	// Stdin selects what the command reads on its standard input. Unbounded and
	// binary-safe, and invisible to other processes on the host — the delivery to reach
	// for when either of those matters.
	Stdin string `json:"stdin,omitempty"`

	// Inline names the source for {{INPUT}} when it appears in an argument, using the
	// same vocabulary as Stdin. Empty means no argument may name {{INPUT}}.
	//
	// A field of its own rather than an overload of Stdin, so Stdin's meaning — what the
	// program reads — stays true, and so a spec can legitimately do both. It is absent
	// on every package installed before inline input existed, which is exactly the right
	// default: {{INPUT}} in an argument is refused unless something says where it comes
	// from, and validateShape says so by name.
	//
	// What this costs relative to Stdin, and what bounds it, is in the package header
	// under "The argv rule, precisely". The short version: bounded by the run's inline
	// budget, text only, and visible in ps.
	Inline string `json:"inline,omitempty"`

	// Files materializes parts of the transaction into the run's scratch directory
	// before the command starts. The key is the placeholder that resolves to the
	// written file's absolute path; the value is which part to write.
	//
	// This is what makes a program that wants a file rather than a pipe work — one whose
	// interface is `-r <file>` rather than stdin — without the bytes ever touching argv.
	Files map[string]string `json:"files,omitempty"`

	// Env is added to a minimal base environment. EnvPass names variables inherited
	// from Joro's own environment.
	//
	// A whitelist rather than an inheritance, which is the opposite of what
	// jsruntime's worker does. That worker inherits Joro's environment and its doc
	// comment says this changes nothing about the sandbox — true there, because the
	// JavaScript global object holds no accessor for an environment. A command has
	// one, so inheriting would put every variable in Joro's environment, including
	// whatever cloud or API credentials the operator's shell exports, into every run.
	Env     map[string]string `json:"env,omitempty"`
	EnvPass []string          `json:"envPass,omitempty"`

	// UseProxy routes the command's HTTP traffic through Joro's own proxy, by setting
	// the conventional proxy and CA-bundle variables in its environment.
	//
	// It is a default, not a control. A command can unset them, and a tool that does
	// its own dialing without consulting them was never bound in the first place —
	// the capability guard's scope rule cannot reach a subprocess. What this buys,
	// when a command does honour them, is that its traffic lands in History under
	// the same scope, noise and Match & Replace the operator's browser gets, which is
	// the same argument the managed testing browser is built on.
	UseProxy bool `json:"useProxy,omitempty"`

	// Redact masks credential header values in whatever reaches the command, by any of
	// the three deliveries: stdin, a file, or an inline {{INPUT}}.
	//
	// Off by default because the usual reason to pipe a request somewhere is to replay
	// it, and replaying an authenticated request with a masked Cookie tests an anonymous
	// endpoint and reports a false negative. On for a command that sends the bytes
	// somewhere Joro does not control.
	Redact bool `json:"redact,omitempty"`

	// Output tells a lens tab how to render stdout. Ignored for a run that is not a
	// lens, which has the run log rather than a tab.
	Output string `json:"output,omitempty"`
}

// Normalize fills defaults and trims. Called before Validate so a spec that omits
// optional fields is accepted rather than corrected by the operator.
func (s *Spec) Normalize() {
	s.Path = strings.TrimSpace(s.Path)
	s.Stdin = strings.ToLower(strings.TrimSpace(s.Stdin))
	s.Inline = strings.ToLower(strings.TrimSpace(s.Inline))
	s.Output = strings.ToLower(strings.TrimSpace(s.Output))

	if s.Stdin == "" {
		s.Stdin = StdinNone
	}
	if s.Output == "" {
		s.Output = OutputText
	}

	// Args are not trimmed. An argument may legitimately need leading or trailing
	// space, and silently editing one would make the spec the operator reads back
	// differ from the spec that runs — the property Render exists to provide.
	if len(s.Args) == 0 {
		s.Args = nil
	}

	// An inline source nothing reads is dropped rather than kept, the same housekeeping
	// Manifest.Normalize does clearing sdkVersion and entrypoint off a command. It also
	// keeps Render honest: a spec that does not use {{INPUT}} must not carry a line
	// claiming a source, or two specs that run identically would hash differently.
	if s.Inline != "" && s.Inline != StdinNone && !s.usesInline() {
		s.Inline = ""
	}
	if s.Inline == StdinNone {
		s.Inline = ""
	}

	s.Files = normalizeMap(s.Files, strings.ToUpper, strings.ToLower)
	s.Env = normalizeMap(s.Env, nil, nil)

	seen := make(map[string]struct{}, len(s.EnvPass))
	kept := make([]string, 0, len(s.EnvPass))
	for _, name := range s.EnvPass {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		kept = append(kept, name)
	}
	if len(kept) == 0 {
		s.EnvPass = nil
	} else {
		s.EnvPass = kept
	}
}

// usesInline reports whether any argument names {{INPUT}}. The one place that question is
// asked, because Normalize, validateShape and the run all have to agree on it.
func (s Spec) usesInline() bool {
	for _, a := range s.Args {
		for _, m := range placeholderPattern.FindAllStringSubmatch(a, -1) {
			if m[1] == PlaceholderInput {
				return true
			}
		}
	}
	return false
}

// normalizeMap trims every key and value, drops empty keys, and applies the optional
// case folds. An empty result becomes nil so an omitempty field disappears rather than
// serializing as {}.
func normalizeMap(m map[string]string, foldKey, foldValue func(string) string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if foldKey != nil {
			k = foldKey(k)
		}
		if foldValue != nil {
			v = foldValue(v)
		}
		if k == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Validate reports why a spec cannot be installed, and resolves Path to an absolute
// executable on success.
//
// It runs at install time rather than at first run, which is the same choice
// jsautomation makes by compiling a script on install: a missing binary or a typo in a
// placeholder is reported to whoever submitted the package while they are still looking
// at it, instead of surfacing hours later as a trigger that quietly fails.
//
// Messages name the field and the rule, because the audience is as often a person
// reading a validation error in a form as it is a reviewer.
func (s *Spec) Validate() error {
	if err := s.validateShape(); err != nil {
		return err
	}
	abs, err := resolveExecutable(s.Path)
	if err != nil {
		return err
	}
	s.Path = abs

	// Only now is the extension known, and it decides whether Windows will hand this to
	// cmd.exe — which has its own rules about what an argument may contain. Checked here
	// so a spec that cannot be represented is refused while its author is still looking
	// at it, rather than at the first run on a Windows host. See cmdline.go.
	if needsCmdEscaping(s.Path) {
		if _, err := cmdCommandLine(s.Path, s.Args); err != nil {
			return err
		}
	}
	return nil
}

// validateShape checks everything that does not touch the filesystem. Split out so a
// caller that only wants to know whether a spec is well-formed — a UI preview, a
// round-trip through a project config on a machine where the tool is not installed —
// can ask without a PATH lookup deciding the answer.
func (s *Spec) validateShape() error {
	switch {
	case s.Path == "":
		return fmt.Errorf("command.path is required: name the executable to run")
	case len(s.Path) > MaxPathLen:
		return fmt.Errorf("command.path is %d characters, over the %d limit", len(s.Path), MaxPathLen)
	case strings.ContainsAny(s.Path, "\x00\n\r"):
		return fmt.Errorf("command.path contains a control character")
	case placeholderPattern.MatchString(s.Path):
		// Substitution is Args-only, so a placeholder here would reach resolveExecutable
		// as a literal and be reported as a missing file — a confusing failure two layers
		// from its cause, and one that reads like a Joro bug rather than a typo.
		return fmt.Errorf("command.path names a {{PLACEHOLDER}}, which is not substituted: " +
			"placeholders resolve in arguments only, and the program has to be decided before " +
			"the run so the binary you review is the one that runs")
	case len(s.Args) > MaxArgs:
		return fmt.Errorf("command.args has %d entries, over the %d limit", len(s.Args), MaxArgs)
	case !slices.Contains(StdinModes, s.Stdin):
		return fmt.Errorf("unknown command.stdin %q (known: %s)", s.Stdin, strings.Join(StdinModes, ", "))
	case s.Inline != "" && !slices.Contains(StdinModes, s.Inline):
		return fmt.Errorf("unknown command.inline %q (known: %s)", s.Inline, strings.Join(StdinModes, ", "))
	case !slices.Contains(OutputModes, s.Output):
		return fmt.Errorf("unknown command.output %q (known: %s)", s.Output, strings.Join(OutputModes, ", "))
	case len(s.Files) > MaxFiles:
		return fmt.Errorf("command.files has %d entries, over the %d limit", len(s.Files), MaxFiles)
	case len(s.Env)+len(s.EnvPass) > MaxEnvVars:
		return fmt.Errorf("command.env and command.envPass name %d variables between them, over the %d limit",
			len(s.Env)+len(s.EnvPass), MaxEnvVars)
	}

	for i, a := range s.Args {
		switch {
		case len(a) > MaxArgLen:
			return fmt.Errorf("command.args[%d] is %d characters, over the %d limit", i, len(a), MaxArgLen)
		case strings.ContainsRune(a, 0):
			return fmt.Errorf("command.args[%d] contains a NUL byte", i)
		}
	}

	for key, part := range s.Files {
		switch {
		case !fileKeyPattern.MatchString(key):
			return fmt.Errorf("command.files key %q is invalid: use uppercase letters, digits and "+
				"underscore, starting with a letter — it is the {{PLACEHOLDER}} that resolves to "+
				"the file's path", key)
		case reservedPlaceholder(key):
			return fmt.Errorf("command.files key %q is reserved: Joro already supplies that "+
				"placeholder", key)
		case !slices.Contains(FileParts, part):
			return fmt.Errorf("unknown command.files[%s] part %q (known: %s)",
				key, part, strings.Join(FileParts, ", "))
		}
	}

	for name, v := range s.Env {
		switch {
		case !envNamePattern.MatchString(name):
			return fmt.Errorf("command.env name %q is not a valid environment variable name", name)
		case len(name) > MaxEnvName:
			return fmt.Errorf("command.env name %q is %d characters, over the %d limit",
				name, len(name), MaxEnvName)
		case len(v) > MaxEnvValue:
			return fmt.Errorf("command.env[%s] is %d characters, over the %d limit",
				name, len(v), MaxEnvValue)
		case strings.ContainsRune(v, 0):
			return fmt.Errorf("command.env[%s] contains a NUL byte", name)
		}
	}
	for _, name := range s.EnvPass {
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("command.envPass entry %q is not a valid environment variable name", name)
		}
	}

	// Every placeholder an argument names has to resolve to something. A typo would
	// otherwise reach the command as a literal "{{REQUEST_FIEL}}", which a tool reads
	// as a filename and reports as missing — a confusing failure two layers from its
	// cause.
	for i, a := range s.Args {
		for _, m := range placeholderPattern.FindAllStringSubmatch(a, -1) {
			name := m[1]
			if _, ok := s.Files[name]; ok {
				continue
			}
			// {{INPUT}} is the one reserved placeholder whose source is declared rather
			// than always available, so it is refused by name until something names it.
			// Refusing here means an operator who typed it without choosing a source is
			// told so while looking at the form, not by a run hours later.
			if name == PlaceholderInput {
				if s.Inline == "" {
					return fmt.Errorf("command.args[%d] names {{INPUT}}, but command.inline does not "+
						"say where the input comes from: choose an input source (%s)",
						i, strings.Join(StdinModes[1:], ", "))
				}
				continue
			}
			if reservedPlaceholder(name) {
				continue
			}
			return fmt.Errorf("command.args[%d] names {{%s}}, which nothing supplies: declare it in "+
				"command.files, or use one of %s", i, name, strings.Join(ReservedPlaceholders(), ", "))
		}
	}
	return nil
}

// Render returns the canonical text of a spec: what will run, one fact per line.
//
// This is a command package's "source", and it carries the same weight a script's does.
// The run log retains it verbatim so an operator reviewing what happened reads the
// actual argv rather than a description of it, and its hash is what the revision
// history tracks — so changing an argument cuts a revision while changing a description
// does not, because a description is not here.
//
// Deterministic: maps are emitted in sorted key order, so an unchanged spec always
// hashes the same regardless of Go's map iteration.
//
// One fact per line, and it stays that way. Rendering the joined command line the editor
// shows would be more readable and would destroy what this is for: a joined line is
// ambiguous about where one argument ends, which is exactly the question a reviewer is
// reading the run log to answer. Spec.Summary is the lossy display form; this is not.
//
// A field added here changes every installed package's hash and cuts a revision on each,
// so a new one is emitted only when it is set — the reason the inline line below is
// conditional rather than always present like stdin.
func (s Spec) Render() string {
	var b strings.Builder

	b.WriteString("exec ")
	b.WriteString(s.Path)
	b.WriteByte('\n')
	for _, a := range s.Args {
		b.WriteString("arg  ")
		b.WriteString(a)
		b.WriteByte('\n')
	}

	b.WriteString("stdin ")
	b.WriteString(orDefault(s.Stdin, StdinNone))
	b.WriteByte('\n')

	if s.Inline != "" && s.Inline != StdinNone {
		b.WriteString("inline ")
		b.WriteString(s.Inline)
		b.WriteByte('\n')
	}

	for _, k := range sortedKeys(s.Files) {
		fmt.Fprintf(&b, "file {{%s}} = %s\n", k, s.Files[k])
	}
	for _, k := range sortedKeys(s.Env) {
		fmt.Fprintf(&b, "env  %s=%s\n", k, s.Env[k])
	}
	for _, name := range slices.Sorted(slices.Values(s.EnvPass)) {
		fmt.Fprintf(&b, "envpass %s\n", name)
	}

	if s.UseProxy {
		b.WriteString("proxy joro\n")
	}
	if s.Redact {
		b.WriteString("redact credentials\n")
	}
	if out := orDefault(s.Output, OutputText); out != OutputText {
		b.WriteString("output ")
		b.WriteString(out)
		b.WriteByte('\n')
	}
	return b.String()
}

// Summary is the one-line form, for a list view.
//
// Lossy and display-only: it joins with spaces, so an argument containing a space reads as
// two and an empty one disappears. Fine for a list row, wrong for anything that has to be
// read back — Render is the canonical form, and the editor's own joiner
// (web/src/lib/cmdline.ts) is the one that round-trips.
func (s Spec) Summary() string {
	parts := make([]string, 0, len(s.Args)+1)
	parts = append(parts, s.Path)
	parts = append(parts, s.Args...)
	line := strings.Join(parts, " ")
	if len(line) > 120 {
		line = line[:117] + "..."
	}
	return line
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Substitutions are the placeholder values for one run, split by where they came from.
//
// Three maps rather than one, so the trust boundary is a property of the type instead of
// a rule someone has to remember. Trusted values go into argv as they are; Captured
// values are held to a grammar first, because a response body an operator is looking at
// came from the target and a URL path is exactly the kind of thing a stored payload
// controls; Bulk holds the transaction's own bytes, which have no grammar to be held to.
type Substitutions struct {
	// Trusted holds values Joro produced: the scratch directory, and the absolute
	// path of each file it wrote there. Nothing from the wire belongs here.
	Trusted map[string]string

	// Captured holds values derived from a captured transaction or an event: HOST,
	// URL, METHOD, STATUS, SEQ, FINDING_ID, CAMPAIGN_ID. Each is validated by
	// checkCaptured against the grammar for its name.
	Captured map[string]string

	// Bulk holds the transaction's own bytes, for {{INPUT}}.
	//
	// A third class because it is neither of the others: far too large for the value
	// cap a Captured entry lives under, and with no grammar available — an HTTP message
	// is whatever the target chose to send, so there is nothing to hold it to. What
	// stands in is a budget and a representability check; see checkBulk.
	Bulk map[string]string
}

// The placeholders Joro supplies. Declared here so validateShape can accept an argument
// that names one and reservedPlaceholder can refuse a Files key that shadows one.
const (
	PlaceholderInput      = "INPUT"
	PlaceholderScratch    = "SCRATCH"
	PlaceholderHost       = "HOST"
	PlaceholderURL        = "URL"
	PlaceholderMethod     = "METHOD"
	PlaceholderStatus     = "STATUS"
	PlaceholderSeq        = "SEQ"
	PlaceholderFindingID  = "FINDING_ID"
	PlaceholderCampaignID = "CAMPAIGN_ID"
)

// placeholderClass says where a placeholder's value comes from, which is what decides the
// checks it faces on the way into argv.
type placeholderClass int

const (
	// classTrusted is a value Joro computed — the scratch directory, a written file's
	// path. No grammar, because it would be checking Joro's own output.
	classTrusted placeholderClass = iota

	// classCaptured is a small value derived from the wire, held to the grammar for its
	// name.
	classCaptured

	// classBulk is the transaction's own bytes. See Substitutions.Bulk.
	classBulk
)

// placeholderRule is one placeholder: what it is, and what a valid value looks like.
//
// One table for both, and that is the point rather than tidiness. The description the
// editor renders and the check a run enforces used to live in two places — a paragraph in
// the frontend and a switch here — which meant a placeholder could be described one way
// and validated another, with nothing to notice. Here a description without a checker
// cannot be constructed and a checker without a description is a visibly empty field, both
// caught by the init below. CLAUDE.md rules out claiming a test pins an invariant, so the
// device has to be structural.
type placeholderRule struct {
	name  string
	class placeholderClass

	// describe is the operator-facing one-liner the editor renders.
	describe string

	// grammar says what a valid value looks like, in the words check enforces.
	grammar string

	// check holds a captured value to that grammar. Required for classCaptured, and nil
	// for the other two, which are checked by their class instead.
	check func(string) error
}

var placeholderRules = []placeholderRule{
	{
		name:  PlaceholderInput,
		class: classBulk,
		describe: "The input source's bytes. Piped on standard input when it leads the command " +
			"line, or substituted into an argument wherever else you write it.",
		grammar: "text with no NUL byte, within the run's inline input budget",
	},
	{
		name:  PlaceholderHost,
		class: classCaptured,
		describe: "Hostname the request went to. Chosen by whatever the browser was talking to, " +
			"so it is held to a grammar before it reaches an argument.",
		grammar: "a hostname or address",
		check: func(v string) error {
			if !isHostLike(v) {
				return fmt.Errorf("{{HOST}} resolved to %q, which is not a hostname or address", v)
			}
			return nil
		},
	},
	{
		name:  PlaceholderURL,
		class: classCaptured,
		describe: "Full URL, including path and query. The whole of it is chosen by the target, " +
			"which makes it the value in this table worth the most care.",
		grammar: "an http or https URL naming a host",
		check: func(v string) error {
			u, err := url.Parse(v)
			if err != nil {
				return fmt.Errorf("{{URL}} resolved to %q, which does not parse as a URL", v)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return fmt.Errorf("{{URL}} resolved to scheme %q; only http and https are substituted",
					u.Scheme)
			}
			if u.Host == "" {
				return fmt.Errorf("{{URL}} resolved to %q, which names no host", v)
			}
			return nil
		},
	},
	{
		name:     PlaceholderMethod,
		class:    classCaptured,
		describe: "The request's HTTP method.",
		grammar:  "letters only",
		check: func(v string) error {
			if !isAlpha(v) {
				return fmt.Errorf("{{METHOD}} resolved to %q, which is not an HTTP method", v)
			}
			return nil
		},
	},
	{
		name:     PlaceholderStatus,
		class:    classCaptured,
		describe: "The response's status code.",
		grammar:  "digits only",
		check: func(v string) error {
			if !isDigits(v) {
				return fmt.Errorf("{{STATUS}} resolved to %q, which is not a number", v)
			}
			return nil
		},
	},
	{
		name:     PlaceholderSeq,
		class:    classCaptured,
		describe: "The request's sequence number in History.",
		grammar:  "digits only",
		check: func(v string) error {
			if !isDigits(v) {
				return fmt.Errorf("{{SEQ}} resolved to %q, which is not a number", v)
			}
			return nil
		},
	},
	{
		name:     PlaceholderFindingID,
		class:    classCaptured,
		describe: "Identifier of the finding that fired this run.",
		grammar:  "an identifier: letters, digits, dash and underscore",
		check: func(v string) error {
			if !isIdentifier(v) {
				return fmt.Errorf("{{FINDING_ID}} resolved to %q, which is not an identifier", v)
			}
			return nil
		},
	},
	{
		name:     PlaceholderCampaignID,
		class:    classCaptured,
		describe: "Identifier of the fuzzing campaign that finished.",
		grammar:  "an identifier: letters, digits, dash and underscore",
		check: func(v string) error {
			if !isIdentifier(v) {
				return fmt.Errorf("{{CAMPAIGN_ID}} resolved to %q, which is not an identifier", v)
			}
			return nil
		},
	},
	{
		name:  PlaceholderScratch,
		class: classTrusted,
		describe: "The run's working directory. The command starts there, and anything it " +
			"leaves behind is collected as an artifact.",
		grammar: "an absolute path Joro created",
	},
}

// The table is the specification, so a malformed entry is a defect in Joro rather than
// something an operator can cause — it fails at startup, next to the mistake.
func init() {
	seen := make(map[string]struct{}, len(placeholderRules))
	for _, r := range placeholderRules {
		switch {
		case !fileKeyPattern.MatchString(r.name):
			panic("localcmd: placeholder rule with an invalid name: " + r.name)
		case r.describe == "":
			panic("localcmd: placeholder " + r.name + " has no description for the editor")
		case r.grammar == "":
			panic("localcmd: placeholder " + r.name + " does not say what a valid value looks like")
		case r.class == classCaptured && r.check == nil:
			panic("localcmd: captured placeholder " + r.name + " has no validation rule")
		case r.class != classCaptured && r.check != nil:
			panic("localcmd: placeholder " + r.name + " carries a check its class never runs")
		}
		if _, dup := seen[r.name]; dup {
			panic("localcmd: duplicate placeholder " + r.name)
		}
		seen[r.name] = struct{}{}
	}
}

// PlaceholderDoc is one placeholder as the editor's reference table shows it.
type PlaceholderDoc struct {
	Name  string `json:"name"`
	Token string `json:"token"`

	Description string `json:"description"`
	Grammar     string `json:"grammar"`

	// Source is the trust class as a word the UI can group on: "joro" for what Joro
	// computed, "captured" for a validated value off the wire, "input" for the
	// transaction's own bytes.
	Source string `json:"source"`
}

// PlaceholderDocs describes every placeholder Joro supplies, in the order the editor
// lists them.
//
// It says what each one is and what a valid value looks like. It does not say which
// triggers supply which — that is not this package's knowledge, and
// jsautomation.CommandPlaceholderAvailability holds it beside the function that decides
// it.
func PlaceholderDocs() []PlaceholderDoc {
	out := make([]PlaceholderDoc, 0, len(placeholderRules))
	for _, r := range placeholderRules {
		out = append(out, PlaceholderDoc{
			Name:        r.name,
			Token:       "{{" + r.name + "}}",
			Description: r.describe,
			Grammar:     r.grammar,
			Source:      r.class.word(),
		})
	}
	return out
}

func (c placeholderClass) word() string {
	switch c {
	case classCaptured:
		return "captured"
	case classBulk:
		return "input"
	default:
		return "joro"
	}
}

// ReservedPlaceholders lists what Joro supplies, for a validation message and for the
// editor's reference panel.
func ReservedPlaceholders() []string {
	out := make([]string, 0, len(placeholderRules))
	for _, r := range placeholderRules {
		out = append(out, "{{"+r.name+"}}")
	}
	return out
}

func reservedPlaceholder(name string) bool {
	return slices.ContainsFunc(placeholderRules, func(r placeholderRule) bool {
		return r.name == name
	})
}

// substitute resolves every {{PLACEHOLDER}} in args.
//
// The refusal rules are the whole point of this function, and each closes a real hole:
//
//   - An unresolved placeholder is an error, never a literal. Passing "{{HOST}}"
//     through to a tool that reads it as a hostname produces a DNS failure nobody can
//     trace back to a typo in a manifest.
//
//   - A substituted value may not begin with "-" *when it begins its argv element*.
//     There is no shell here, so the classic injection is closed already — but argument
//     injection is not: a URL whose query happens to read "-oProxyCommand=..." or
//     "--output=/etc/cron.d/x" becomes an option rather than a value the moment it lands
//     at the start of an element.
//
//     The position is the whole rule, and checking it is what makes the rule exact
//     rather than merely strict. Being read as an option requires occupying position 0
//     of an element: "--data={{INPUT}}" is a value however it starts, because the
//     command already read "--data=" as the option. Refusing a dash there too would
//     block a body that begins with one — YAML, a diff, a CSV — and buy nothing.
//
//   - A substituted value may not contain a NUL, and, unless it is Bulk, may not contain
//     a newline and is length-capped. Those are shapes no host, URL or identifier has.
//     A Bulk value is an HTTP message, which is nothing but lines, so it is held to
//     checkBulk instead.
//
// A Trusted value skips the grammar check but not the control-character and length
// checks: Joro computes those paths, so the grammar would be checking its own output,
// but a scratch path is still going into argv and the cheap checks are worth keeping
// unconditional.
func substitute(args []string, sub Substitutions, maxInline int) ([]string, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(args))

	// Counted across the whole argv rather than per argument, because what the platform
	// refuses is the total: two arguments each just inside the budget would still be an
	// exec Joro promised would work and the kernel declines.
	inlineUsed := 0

	for i, a := range args {
		var b strings.Builder
		last := 0

		for _, idx := range placeholderPattern.FindAllStringSubmatchIndex(a, -1) {
			name := a[idx[2]:idx[3]]

			value, class, ok := sub.lookup(name)
			if !ok {
				return nil, fmt.Errorf("args[%d] names {{%s}}, which this run has no value for", i, name)
			}
			// A match starting at byte 0 is the only one whose value can begin the
			// element: every earlier placeholder resolved to something non-empty, and
			// literal text before it would have pushed this one along.
			if err := checkSubstituted(name, value, class, idx[0] == 0); err != nil {
				return nil, fmt.Errorf("args[%d]: %w", i, err)
			}
			if class == classBulk {
				inlineUsed += len(value)
				if err := checkInlineBudget(inlineUsed, maxInline); err != nil {
					return nil, fmt.Errorf("args[%d]: %w", i, err)
				}
			}

			b.WriteString(a[last:idx[0]])
			b.WriteString(value)
			last = idx[1]
		}

		b.WriteString(a[last:])
		out = append(out, b.String())
	}
	return out, nil
}

// ErrInlineTooLarge is what substitute returns when {{INPUT}} would put more bytes into
// argv than the run allows. A sentinel because Run maps it to its own termination reason:
// "not permitted" would send an operator looking for a grant, where the two real fixes are
// a larger budget or stdin.
var ErrInlineTooLarge = errors.New("inline input over budget")

func checkInlineBudget(used, budget int) error {
	switch {
	case budget <= 0:
		return fmt.Errorf("%w: the inline input budget is zero, so {{INPUT}} cannot be put in an "+
			"argument on this instance. Pipe it on standard input instead, or raise the budget "+
			"in the run budget settings", ErrInlineTooLarge)
	case used > budget:
		return fmt.Errorf("%w: {{INPUT}} needs %d bytes in the command line, over the %d byte "+
			"budget. Pipe it on standard input instead, which has no size limit, or raise the "+
			"budget in the run budget settings", ErrInlineTooLarge, used, budget)
	}
	return nil
}

// lookup finds a placeholder's value and reports which class it belongs to. Trusted is
// consulted first, so nothing can shadow a scratch path.
func (s Substitutions) lookup(name string) (value string, class placeholderClass, ok bool) {
	if v, found := s.Trusted[name]; found {
		return v, classTrusted, true
	}
	if v, found := s.Bulk[name]; found {
		return v, classBulk, true
	}
	if v, found := s.Captured[name]; found {
		return v, classCaptured, true
	}
	return "", classTrusted, false
}

// checkSubstituted holds one resolved value to the rules substitute documents.
func checkSubstituted(name, value string, class placeholderClass, atStart bool) error {
	if value == "" {
		return fmt.Errorf("{{%s}} resolved to an empty value", name)
	}
	if atStart && strings.HasPrefix(value, "-") {
		return fmt.Errorf("{{%s}} resolved to a value starting with a dash, and it starts the "+
			"argument, so it is refused. A value in that position is read as an option rather "+
			"than an argument, which is how an attacker-influenced URL or host turns into a flag "+
			"the command was never given — putting it after a prefix such as --flag= is enough "+
			"to make it a value again", name)
	}

	if class == classBulk {
		return checkBulk(name, value)
	}

	switch {
	case len(value) > maxSubstValue:
		return fmt.Errorf("{{%s}} resolved to %d characters, over the %d limit",
			name, len(value), maxSubstValue)
	case strings.ContainsAny(value, "\x00\n\r"):
		return fmt.Errorf("{{%s}} resolved to a value containing a control character, which is "+
			"refused: no legitimate host, URL or identifier holds one", name)
	}

	if class == classTrusted {
		return nil
	}
	return checkCaptured(name, value)
}

// checkBulk holds the transaction's own bytes to what an argument can physically carry.
//
// Both refusals are the operating system's rather than Joro's, which is why neither has a
// setting and why both name stdin: that delivery has neither problem. The length is the
// third limit and is a budget rather than a check, so it lives in checkInlineBudget where
// the running total is.
//
// A newline is deliberately not refused here, unlike for every other class. The rule
// elsewhere exists because no host or identifier holds one; an HTTP message is nothing but
// lines, so refusing them would refuse the feature. On Windows a cmd.exe-parsed target
// still cannot represent one, and applyCmdLine catches that after substitution.
func checkBulk(name, value string) error {
	if i := strings.IndexByte(value, 0); i >= 0 {
		return fmt.Errorf("{{%s}} resolved to bytes with a NUL at offset %d, which an argument "+
			"cannot hold: argv is a list of NUL-terminated strings, so this is the operating "+
			"system's limit and not a setting. Pipe the input on standard input instead, which "+
			"is binary-safe", name, i)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("{{%s}} resolved to bytes that are not valid UTF-8, which an argument "+
			"cannot carry unchanged: Windows re-encodes argv to UTF-16 and would corrupt them. "+
			"Pipe the input on standard input instead, which is binary-safe", name)
	}
	return nil
}

// checkCaptured holds a value derived from the wire to the grammar for its name.
//
// A default of "refuse" rather than "allow": a placeholder added to placeholderRules
// without a checker fails every run that uses it, which is the loud failure. Allowing it
// through unchecked would be the silent one — though the init above means it cannot be
// added that way in the first place.
func checkCaptured(name, value string) error {
	for _, r := range placeholderRules {
		if r.name == name && r.check != nil {
			return r.check(value)
		}
	}
	return fmt.Errorf("{{%s}} has no validation rule, so it is refused. This is a defect in "+
		"Joro: a placeholder was declared without stating what a valid value looks like", name)
}

func isHostLike(s string) bool {
	if len(s) > 255 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == ':' || r == '_' || r == '[' || r == ']':
		default:
			return false
		}
	}
	return true
}

func isAlpha(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return s != ""
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func isIdentifier(s string) bool {
	if len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return s != ""
}

// Result is the outcome of a run.
//
// Always returned, including on failure: a command that timed out still has whatever it
// wrote before it was stopped, and that is usually what explains it.
type Result struct {
	Reason  string `json:"reason"`
	Outcome string `json:"outcome"`

	// Err carries Joro's own explanation when the run did not happen or could not be
	// completed. Never a Go error string with a wrapped chain — the audience is a
	// person reading the run log.
	Err string `json:"err,omitempty"`

	// ExitCode is the process's exit status, or -1 when it never reported one
	// (killed, or never started).
	ExitCode int `json:"exitCode"`

	Stdout          []byte `json:"-"`
	Stderr          []byte `json:"-"`
	StdoutTruncated bool   `json:"stdoutTruncated,omitempty"`
	StderrTruncated bool   `json:"stderrTruncated,omitempty"`

	Artifacts []Artifact `json:"artifacts,omitempty"`

	// Limits is what this run was actually held to, after the operator's policy was
	// applied. Reported rather than left implicit, for the same reason jsruntime
	// reports it: a truncation flag with nothing to read it against explains nothing.
	Limits     Budget `json:"limits"`
	DurationMs int64  `json:"durationMs"`
}

// OK reports whether the command ran and exited zero.
func (r Result) OK() bool { return r.Reason == ReasonSuccess }

// Limits bound one run, in the runtime's own units. A zero field takes the default.
//
// There is no memory field; see the header of budget.go for why the process boundary
// already provides what one would buy.
type Limits struct {
	Timeout time.Duration

	MaxStdoutBytes int
	MaxStderrBytes int

	// MaxArtifactBytes bounds the total the scratch directory may hold when artifacts
	// are collected. A command that fills the disk is the operator's problem either
	// way; this bounds what Joro then reads and retains.
	MaxArtifactBytes int64

	// MaxInlineInputBytes bounds what {{INPUT}} may put into argv, across the whole
	// argument list. Zero switches inline input off rather than taking a default, which
	// is the one place a zero here does not mean "unset" — see Fill.
	MaxInlineInputBytes int
}

// Fill supplies a default for any field left at zero and enforces the absolute caps.
//
// Deliberately does not apply the stock maxima — the same split jsruntime.Limits.Fill
// documents. Those maxima bound what a caller may *ask for*, and that question is
// settled once against the operator's policy before Limits reaches this package. By the
// time it does, the numbers are a resolved budget rather than a request, so re-applying
// a stock maximum here would silently lower a limit the operator raised.
func (l Limits) Fill() Limits {
	l.Timeout = clampDuration(l.Timeout, DefaultTimeout, CapTimeout)
	l.MaxStdoutBytes = clamp(l.MaxStdoutBytes, DefaultMaxStdoutBytes, 0)
	l.MaxStderrBytes = clamp(l.MaxStderrBytes, DefaultMaxStderrBytes, 0)
	l.MaxArtifactBytes = clamp(l.MaxArtifactBytes, DefaultMaxArtifactBytes, 0)
	// The one field Fill does cap, because its ceiling is not a policy an earlier layer
	// resolved but a limit of the platform: over it the exec simply fails.
	l.MaxInlineInputBytes = clamp(l.MaxInlineInputBytes, DefaultMaxInlineInputBytes, CapInlineInputBytes)
	return l
}
