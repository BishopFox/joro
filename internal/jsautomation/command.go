package jsautomation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/jsruntime"
	"github.com/BishopFox/joro/internal/localcmd"
)

// The command half of a run.
//
// A command automation's body is a localcmd.Spec rather than a script, and this file is
// everything Joro has to decide before handing that spec to a process: which transaction
// it is looking at, what bytes go on its stdin, what it may see in argv, and how what came
// back becomes a run record the operator reads the same way they read a script's.
//
// # Where the bytes come from, and why that differs from a script
//
// A trigger hands a script *references* — a request sequence number, a finding id — and
// never content. That split is deliberate and triggers.go states it: being handed an event
// is not permission to read what it is about, so a script resolves detail through
// joro.http.read where its own principal is enforced.
//
// A command has no principal. There is no capability to invoke, so there is nothing for a
// guard to evaluate and no second chance to refuse. Joro therefore resolves the bytes
// itself, here, and the thing standing in for that guard is the operator having installed
// and armed this package. That is a real difference in kind and not a shortcut: a command
// automation is trusted the way a lens is, at the moment it is enabled, rather than call by
// call.
//
// # One event per run
//
// The dispatcher batches, because for a script one run per interval handling fifty events
// is what makes a traffic trigger affordable at all. A command cannot use a batch: its
// stdin is one transaction's bytes and its argv holds one transaction's URL, so fifty
// references have nowhere to go.
//
// So a command run is handed exactly one event — the newest in the batch — and the payload
// says how many it did not see. A command on a traffic trigger therefore *samples* traffic
// rather than processing all of it, which is also what the cursor rule in triggers.go
// already does for it. Documented rather than hidden, because an operator expecting every
// request to be scanned would otherwise draw the wrong conclusion from an empty result.

// maxStderrLines bounds how many lines of stderr become log lines, independently of the
// byte budget. A tool that prints a million single-character lines fits inside a modest
// byte cap and would still produce a log nothing can render.
const maxStderrLines = 2000

// commandScratchDir is the directory under the data dir that holds per-run scratch.
const commandScratchDir = "cmdruns"

// commandContext is the operator-or-viewer-supplied half of a run's input: what History's
// context menu sends for a selected request, and what the viewer sends for a lens.
//
// Both arrive in RunRequest.Input rather than TriggerData, because neither is an event —
// the operator started them.
type commandContext struct {
	// Part and Raw are the lens contract: the bytes already on screen, base64-encoded,
	// and which half of the transaction they are.
	Part      string `json:"part,omitempty"`
	Raw       string `json:"raw,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`

	Seq    int    `json:"seq,omitempty"`
	Host   string `json:"host,omitempty"`
	URL    string `json:"url,omitempty"`
	Method string `json:"method,omitempty"`
	Status int    `json:"status,omitempty"`
}

// commandBatch is the dispatcher's payload, read back through the fields a focus needs.
// Only ever one element long for a command; see the file header.
type commandBatch struct {
	Requests  []requestRef     `json:"requests,omitempty"`
	Findings  []findingFields  `json:"findings,omitempty"`
	Campaigns []campaignFields `json:"campaigns,omitempty"`
	Dropped   int              `json:"dropped,omitempty"`
}

// commandFocus is the one transaction or event a command run is about.
type commandFocus struct {
	seq    int
	host   string
	url    string
	method string
	status int

	findingID  string
	campaignID string

	reqRaw  []byte
	respRaw []byte
}

// captured builds the validated half of the substitution set: values that came from the
// wire, and which localcmd holds to a grammar before letting one near argv.
//
// Only non-empty values are included. A placeholder with no value is refused by name at
// substitution time, which is a better failure than an empty string reaching a tool as an
// argument it reads as something else.
//
// Which of these are actually populated depends on the trigger, and that is what
// CommandPlaceholderAvailability below reports to the editor. Adding a placeholder here
// means adding it there: the table is what lets the editor warn while the operator is
// looking at the form, instead of the run failing hours later on a name it had no value
// for.
func (f commandFocus) captured() map[string]string {
	out := make(map[string]string, 7)
	put := func(k, v string) {
		if v != "" {
			out[k] = v
		}
	}
	put(localcmd.PlaceholderHost, f.host)
	put(localcmd.PlaceholderURL, f.url)
	put(localcmd.PlaceholderMethod, f.method)
	put(localcmd.PlaceholderFindingID, f.findingID)
	put(localcmd.PlaceholderCampaignID, f.campaignID)
	if f.seq > 0 {
		out[localcmd.PlaceholderSeq] = strconv.Itoa(f.seq)
	}
	if f.status > 0 {
		out[localcmd.PlaceholderStatus] = strconv.Itoa(f.status)
	}
	return out
}

// CommandPlaceholderAvailability reports which placeholders each trigger supplies a value
// for, keyed by trigger id and by TriggerLens.
//
// It lives here rather than in localcmd because it is not that package's knowledge:
// localcmd is a leaf and cannot name a trigger constant, and what populates a value is
// resolveFocus and captured, twenty lines up. Keeping the table beside them is the whole
// anti-drift device — the note that matters is the one on captured, because that is the
// function someone edits.
//
// Every entry names only what the trigger genuinely carries. A finding or a campaign
// carries no transaction, so neither supplies HOST, URL or the rest; the reciprocal is why
// a request trigger does not supply FINDING_ID. {{SCRATCH}} and a file placeholder are
// always available and are deliberately absent, since a table of "always" tells the
// operator nothing — the editor adds them.
func CommandPlaceholderAvailability() map[string][]string {
	transaction := []string{
		localcmd.PlaceholderInput,
		localcmd.PlaceholderHost,
		localcmd.PlaceholderURL,
		localcmd.PlaceholderMethod,
		localcmd.PlaceholderStatus,
		localcmd.PlaceholderSeq,
	}
	return map[string][]string{
		// Free-form: the operator supplies the input themselves, so anything a
		// transaction carries may be there and nothing is guaranteed.
		TriggerManual: transaction,

		TriggerRequestSelected: transaction,
		TriggerRequestCaptured: transaction,
		TriggerLens:            transaction,

		TriggerDetectFinding: {
			localcmd.PlaceholderInput,
			localcmd.PlaceholderFindingID,
			localcmd.PlaceholderHost,
		},
		TriggerFuzzerComplete: {
			localcmd.PlaceholderInput,
			localcmd.PlaceholderCampaignID,
		},

		// A finished run carries no transaction and no finding — only what the run itself
		// was and returned, which reaches the command through {{INPUT}} as the trigger
		// payload. There is nothing else honest to offer here.
		TriggerAutomationCompleted: {
			localcmd.PlaceholderInput,
		},
	}
}

// resolveFocus works out what this run is looking at, from the operator's input and the
// dispatcher's payload, and fetches the transaction's bytes if it needs them.
//
// Input wins over TriggerData where both name something. The two never both carry a focus
// on any real path — a lens has no trigger data and a trigger has no input — so the
// precedence only decides a case that does not arise, and stating it is cheaper than
// leaving it to whichever unmarshal ran last.
func (m *Manager) resolveFocus(req RunRequest) commandFocus {
	var f commandFocus

	var ctx commandContext
	if len(req.Input) > 0 {
		// A failure here is not worth reporting: Input is free-form on the manual path,
		// so an operator's test payload that is not a transaction is a normal thing to
		// send and simply supplies no focus.
		_ = json.Unmarshal(req.Input, &ctx)
	}
	f.seq, f.host, f.url, f.method, f.status = ctx.Seq, ctx.Host, ctx.URL, ctx.Method, ctx.Status

	// The lens path hands over the bytes directly, which is the whole shape of a lens:
	// it transforms what is already on screen, so re-reading it from the store could
	// disagree with what the operator is looking at.
	if ctx.Raw != "" {
		if raw, err := base64.StdEncoding.DecodeString(ctx.Raw); err == nil {
			switch ctx.Part {
			case localcmd.PartRequest:
				f.reqRaw = raw
			default:
				f.respRaw = raw
			}
		}
	}

	if len(req.TriggerData) > 0 {
		var b commandBatch
		if json.Unmarshal(req.TriggerData, &b) == nil {
			if n := len(b.Requests); n > 0 {
				r := b.Requests[n-1]
				f.seq, f.host, f.url, f.method, f.status = r.Seq, r.Host, r.URL, r.Method, r.Status
			}
			if n := len(b.Findings); n > 0 {
				fd := b.Findings[n-1]
				f.findingID = fd.ID
				if f.host == "" {
					f.host = fd.Host
				}
			}
			if n := len(b.Campaigns); n > 0 {
				f.campaignID = b.Campaigns[n-1].CampaignID
			}
		}
	}

	// Fetch only what the lens did not already supply. Captures is a narrow getter
	// rather than the capture store itself, for the reason Deps documents.
	if f.seq > 0 && f.reqRaw == nil && f.respRaw == nil && m.deps.Captures != nil {
		if reqRaw, respRaw, ok := m.deps.Captures(f.seq); ok {
			f.reqRaw, f.respRaw = reqRaw, respRaw
		}
	}
	return f
}

// partBytes returns the bytes for one of the Stdin or Files part names, with credential
// masking applied when the spec asked for it.
//
// Masking is length-preserving, so an offset a command reports still lines up with what
// History shows — the property httptools.MaskHeaders exists to provide.
func (f commandFocus) partBytes(part string, redact bool, trigger json.RawMessage) []byte {
	mask := func(b []byte) []byte {
		if !redact || len(b) == 0 {
			return b
		}
		masked, _ := httptools.MaskHeaders(b)
		return masked
	}

	switch part {
	case localcmd.PartRequest:
		return mask(f.reqRaw)
	case localcmd.PartResponse:
		return mask(f.respRaw)
	case localcmd.PartBoth:
		req, resp := mask(f.reqRaw), mask(f.respRaw)
		switch {
		case len(req) == 0:
			return resp
		case len(resp) == 0:
			return req
		}
		// A blank line between them, which is what separates a message from what
		// follows it on the wire, so a tool parsing HTTP sees two messages rather than
		// one malformed one.
		out := make([]byte, 0, len(req)+len(resp)+4)
		out = append(out, req...)
		out = append(out, '\r', '\n', '\r', '\n')
		return append(out, resp...)
	case localcmd.PartTrigger:
		return trigger
	}
	return nil
}

// runCommand executes a command automation and returns its outcome in the run record's
// shape.
//
// It reports through jsruntime.Result rather than a second result type, and that is worth
// stating plainly: the run log, the operator's run output panel, the sidecar's last-run
// pointer and the lens contract are all written against that struct, and a parallel one
// would mean a parallel of each. Every field either maps or stays zero — see cmdResult —
// and nothing in jsruntime knows this path exists.
func (m *Manager) runCommand(ctx context.Context, runID string, req RunRequest) (jsruntime.Result, error) {
	spec := *req.Command

	if !m.commandsEnabled() {
		return jsruntime.Result{
			Reason: localcmd.ReasonNotPermitted,
			Err: "local command automations are not enabled on this instance. Start Joro with " +
				"--automation-commands to allow them; the package stays installed either way.",
		}, nil
	}
	if m.deps.Scratch == "" {
		return jsruntime.Result{
			Reason: localcmd.ReasonRuntimeFailure,
			Err:    "no scratch directory is configured for command automations",
		}, nil
	}

	scratch := filepath.Join(m.deps.Scratch, runID)
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return jsruntime.Result{
			Reason: localcmd.ReasonSpawnFailed,
			Err:    fmt.Sprintf("the run's working directory could not be created: %v", err),
		}, nil
	}
	// Prune after the run rather than before, so this run's own directory is the newest
	// and is never the one reclaimed.
	defer m.pruneScratch()

	focus := m.resolveFocus(req)

	inputs, trusted, err := writeInputs(scratch, spec, focus, req.TriggerData)
	if err != nil {
		return jsruntime.Result{
			Reason: localcmd.ReasonSpawnFailed,
			Err:    err.Error(),
		}, nil
	}
	trusted[localcmd.PlaceholderScratch] = scratch

	var stdin *bytes.Reader
	if spec.Stdin != localcmd.StdinNone {
		stdin = bytes.NewReader(focus.partBytes(spec.Stdin, spec.Redact, req.TriggerData))
	}

	// The same accessor the other two deliveries use, so masking, the blank line between
	// a request and its response, and the trigger payload all behave identically whether
	// the bytes end up on stdin, in a file, or in an argument. What differs is only what
	// localcmd will accept of them, which is its business rather than this file's.
	var bulk map[string]string
	if spec.Inline != "" && spec.Inline != localcmd.StdinNone {
		bulk = map[string]string{
			localcmd.PlaceholderInput: string(focus.partBytes(spec.Inline, spec.Redact, req.TriggerData)),
		}
	}

	res, err := localcmd.Run(ctx, spec, stdin, localcmd.RunOpts{
		Limits:  req.CommandLimits,
		Scratch: scratch,
		Inputs:  inputs,
		Subst: localcmd.Substitutions{
			Trusted:  trusted,
			Captured: focus.captured(),
			Bulk:     bulk,
		},
		ProxyURL: m.deps.ProxyURL,
		CAFile:   m.deps.CAFile,
	})
	if err != nil {
		return jsruntime.Result{Reason: localcmd.ReasonRuntimeFailure, Err: err.Error()}, nil
	}
	return cmdResult(res, spec), nil
}

// writeInputs materializes the parts a spec asked for into the run's scratch directory and
// returns their base names plus the placeholder-to-path map.
//
// The names are Joro's, derived from the placeholder, and never anything from the wire. A
// filename taken from a captured URL would be a path traversal with extra steps.
func writeInputs(scratch string, spec localcmd.Spec, focus commandFocus,
	trigger json.RawMessage) (names []string, trusted map[string]string, err error) {
	trusted = make(map[string]string, len(spec.Files)+1)
	if len(spec.Files) == 0 {
		return nil, trusted, nil
	}

	for _, key := range sortedFileKeys(spec.Files) {
		part := spec.Files[key]
		name := strings.ToLower(key) + ".bin"
		path := filepath.Join(scratch, name)

		body := focus.partBytes(part, spec.Redact, trigger)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return nil, nil, fmt.Errorf("writing the %s input file: %w", part, err)
		}
		names = append(names, name)
		trusted[key] = path
	}
	return names, trusted, nil
}

func sortedFileKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// commandValue is what a command run returns, and it is one shape for two readers.
//
// A lens reads text and language and ignores the rest, which is the existing lens contract
// and the reason a command lens needed no frontend change at all. The run output panel
// reads the exit code and the artifacts as well. Emitting two shapes depending on the
// trigger would have meant a consumer that had to know which one it was looking at.
type commandValue struct {
	Text     string `json:"text"`
	Language string `json:"language,omitempty"`

	ExitCode  int  `json:"exitCode"`
	Truncated bool `json:"truncated,omitempty"`

	// Binary means Text is base64 rather than the bytes themselves, because stdout was
	// not valid UTF-8. Flagged rather than silently replaced, so a hex dump of a binary
	// response is not mistaken for a tool that printed rubbish.
	Binary bool `json:"binary,omitempty"`

	Artifacts []localcmd.Artifact `json:"artifacts,omitempty"`
}

// cmdResult maps a command's outcome onto the run record shape.
//
// The mapping, and why each half goes where it does:
//
//   - stderr becomes the run's log. It is the running commentary of what happened, which
//     is what a log is, and it renders in the same panel a script's console output does.
//   - stdout becomes the returned value, because it is the answer. A lens renders it as
//     its tab; a triggered run leaves it in the log for the operator to read.
//   - Calls, SendCalls and StorageOps stay zero. A command makes no SDK calls, and
//     reporting a fabricated count would be worse than reporting none.
//   - Budget stays zero for the same reason: those are the script budget's fields, and
//     the command budget is reported inside the value instead.
func cmdResult(res localcmd.Result, spec localcmd.Spec) jsruntime.Result {
	text, binary := renderStdout(res.Stdout)

	value := commandValue{
		Text:      text,
		ExitCode:  res.ExitCode,
		Truncated: res.StdoutTruncated,
		Binary:    binary,
		Artifacts: res.Artifacts,
	}
	if spec.Output == localcmd.OutputJSON {
		value.Language = "json"
	}

	out := jsruntime.Result{
		Reason:        res.Reason,
		Outcome:       res.Outcome,
		Err:           res.Err,
		Logs:          stderrLines(res.Stderr),
		LogsTruncated: res.StderrTruncated,
		DurationMs:    res.DurationMs,
	}
	if encoded, err := json.Marshal(value); err == nil {
		out.Value = encoded
	} else {
		// A value that will not marshal is Joro's bug, not the command's, and the run
		// should say so rather than reporting an empty success.
		out.Reason = localcmd.ReasonRuntimeFailure
		out.Outcome = localcmd.OutcomeRuntimeFailure
		out.Err = fmt.Sprintf("the command's output could not be encoded: %v", err)
	}
	return out
}

// renderStdout returns stdout as text, or base64 when it is not valid UTF-8.
func renderStdout(b []byte) (text string, binary bool) {
	if len(b) == 0 {
		return "", false
	}
	if utf8.Valid(b) {
		return string(b), false
	}
	return base64.StdEncoding.EncodeToString(b), true
}

// stderrLines turns stderr into log lines.
//
// Level "error" throughout, which overstates some of it — plenty of tools write progress
// to stderr — but the alternative is guessing from the text, and a wrong guess that
// renders a real error as ordinary output is the more expensive mistake.
func stderrLines(b []byte) []jsruntime.LogLine {
	if len(b) == 0 {
		return nil
	}
	raw := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(raw) > maxStderrLines {
		raw = raw[:maxStderrLines]
	}
	out := make([]jsruntime.LogLine, 0, len(raw))
	for _, line := range raw {
		out = append(out, jsruntime.LogLine{Level: "error", Text: strings.TrimRight(line, "\r")})
	}
	return out
}

// pruneScratch removes the oldest run directories past the operator's retention figure.
//
// Best effort and silent: a run that worked must not be reported as failed because a
// cleanup did not. Newest-first by modification time, which for a directory Joro created
// per run and never touches again is its creation time.
func (m *Manager) pruneScratch() {
	if m.deps.Scratch == "" {
		return
	}
	keep := m.commandPolicy().Host.Resolved().ScratchRuns

	entries, err := os.ReadDir(m.deps.Scratch)
	if err != nil {
		return
	}
	type dirAge struct {
		name string
		mod  int64
	}
	dirs := make([]dirAge, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		dirs = append(dirs, dirAge{name: e.Name(), mod: info.ModTime().UnixNano()})
	}
	if len(dirs) <= keep {
		return
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].mod > dirs[j].mod })
	for _, d := range dirs[keep:] {
		_ = os.RemoveAll(filepath.Join(m.deps.Scratch, d.name))
	}
}

// SweepScratch prunes leftover run directories at startup.
//
// Called once by the wiring rather than left to the first run, because a Joro that is
// restarted more often than it runs a command would otherwise accumulate directories from
// every previous process.
func (m *Manager) SweepScratch() { m.pruneScratch() }

// ScratchDirName is the data-dir subdirectory holding per-run scratch. Exported so the
// wiring names it in one place rather than repeating the literal.
func ScratchDirName() string { return commandScratchDir }

// ErrNoArtifact means a run has no retained file by that name.
var ErrNoArtifact = errors.New("no such artifact")

// ArtifactPath resolves one of a run's artifacts to a path on disk.
//
// The path is built here rather than in the API layer because this package owns the
// scratch layout, and a route that joined the pieces itself would be a second place the
// containment rules had to hold.
//
// Three checks, and each is load-bearing:
//
//  1. The run has to be in the run log. That is what stops the endpoint being a reader for
//     arbitrary directory names — a caller can only name a run Joro is still retaining.
//  2. The run id has to look like one. Store.path validates an automation id again at the
//     join rather than trusting an earlier check, and the same argument applies here: a
//     store whose only defense against traversal lives in a caller is one refactor away
//     from not having one.
//  3. filepath.Localize refuses an absolute path, a parent reference, or anything else
//     that would not stay inside the directory. It is the standard library's own answer to
//     this question, which beats hand-rolling a Clean-and-prefix-check.
func (m *Manager) ArtifactPath(runID, name string) (string, error) {
	if m.deps.Scratch == "" {
		return "", ErrNoArtifact
	}
	if _, ok := m.runs.Get(runID); !ok {
		return "", ErrNoArtifact
	}
	if !runIDPattern.MatchString(runID) {
		return "", ErrNoArtifact
	}
	rel, err := filepath.Localize(name)
	if err != nil {
		return "", ErrNoArtifact
	}

	path := filepath.Join(m.deps.Scratch, runID, rel)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return "", ErrNoArtifact
	}
	return path, nil
}

// runIDPattern is the shape newRunID produces. Checked at the join for the reason
// ArtifactPath states.
var runIDPattern = regexp.MustCompile(`^run_[0-9a-f]{16}$`)
