package chain

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/joro/internal/httptools"
)

// Vars is the value table a run accumulates as it walks a variant.
type Vars map[string]string

// Missing names one unresolved dependency: a value a step needs that nothing has
// produced yet in this variant.
type Missing struct {
	Var      string `json:"var"`
	FromStep string `json:"fromStep"`
}

// Render produces the bytes for one step instance.
//
// The order is forced by correctness and is not a preference:
//
//  1. Binding spans, descending by offset. Offsets are computed against the
//     pristine snapshot, so applying them high-to-low keeps every remaining
//     offset valid no matter how much the replacement changes length.
//  2. Manual edits, so an operator can override a bound value rather than
//     fighting it.
//  3. Content-Length, unconditionally. Step 1 changes the body length whenever a
//     bound value moves into it, and skipping this produces a request the origin
//     reads as truncated — which is indistinguishable from the server rejecting
//     the replay, and so is the exact failure this feature must never produce.
//
// A binding whose value is missing and whose OnMissing is MissingFail is reported
// rather than guessed at; the caller must not send.
func Render(chain *Chain, step Step, vars Vars) (raw []byte, missing []Missing, err error) {
	type patch struct {
		span  Span
		value string
	}
	var patches []patch

	for _, b := range chain.BindingsInto(step.ID) {
		val, ok := vars[b.Var]
		if !ok {
			if b.OnMissing != MissingRecorded {
				missing = append(missing, Missing{Var: b.Var, FromStep: b.FromStep})
				continue
			}
			val = b.Recorded
		}
		for _, sp := range b.Spans {
			if sp.Start < 0 || sp.End > len(step.ReqRaw) || sp.Start > sp.End {
				return nil, nil, fmt.Errorf("binding %s has a span outside the recorded request", b.Var)
			}
			patches = append(patches, patch{span: sp, value: val})
		}
	}
	if len(missing) > 0 {
		return nil, missing, nil
	}

	// Descending by start. Equal starts keep a stable order; overlapping spans
	// are refused by validation, so there is no last-writer question here.
	sort.SliceStable(patches, func(i, j int) bool {
		return patches[i].span.Start > patches[j].span.Start
	})

	out := append([]byte(nil), step.ReqRaw...)
	for _, p := range patches {
		out = append(out[:p.span.Start], append([]byte(p.value), out[p.span.End:]...)...)
	}

	if len(step.Edits) > 0 {
		out, err = httptools.ApplyEdits(out, step.Edits)
		if err != nil {
			return nil, nil, fmt.Errorf("edits: %w", err)
		}
	}

	return httptools.UpdateContentLength(out), nil, nil
}

// Capture runs every source a step produces against its response and folds the
// results into vars.
//
// Failures are returned rather than swallowed, but they are not fatal on their
// own: a source that did not fire only matters when a later step actually needs
// the value, and that is where it becomes an unresolved dependency with a name
// attached. Reporting it here too is what lets the UI show "step 2 did not
// produce csrf" beside the step rather than only beside its consumer.
func Capture(chain *Chain, step Step, respRaw []byte, vars Vars) []string {
	resp := httptools.ReadResponse(respRaw)

	seen := make(map[string]bool)
	var problems []string
	for _, b := range chain.BindingsFrom(step.ID) {
		// One value may feed several steps as several bindings; extract once.
		if seen[b.Var] {
			continue
		}
		seen[b.Var] = true

		val, err := Extract(b.Source, resp)
		if err != nil {
			// A repeat re-runs a producer against a table still holding what it
			// produced last time. Leaving the stale entry makes Render send a
			// spent token, and the rejection reads as the application enforcing
			// its order rather than as an unresolved dependency.
			delete(vars, b.Var)
			problems = append(problems, fmt.Sprintf("%s: %v", b.Var, err))
			continue
		}
		vars[b.Var] = val
	}
	return problems
}

// Canonicalize rewrites a response, replacing every value the run has bound with
// its variable name.
//
// This is what makes two runs of one chain comparable, and it is the reason a
// chain is worth building rather than diffing raw responses.
//
// httptools.FingerprintResponse already folds out values a server would have
// chosen differently — hex runs, UUIDs, timestamps, base64 — but it can only
// fold what its patterns recognize. An identifier like "ord_4025aff0ad" matches
// none of them: the underscore denies the hex rule its word boundary, and the
// string is too short for the base64 rule, so it falls through to the bare-digit
// rule and normalizes to a different shape on every run. The consequence is not
// cosmetic: every replayed step reads as "changed", every skip reads as
// "enforced", and the tab confidently reports that an application is safe.
//
// A chain does not have to guess. The values that vary between runs are exactly
// the ones it bound, and it holds both the names and the current values. Folding
// those first means the remaining differences are real ones.
//
// Only ever applied to the copy that is hashed. What was sent and what is shown
// to the operator are untouched.
func Canonicalize(raw []byte, vars Vars) []byte {
	if len(raw) == 0 || len(vars) == 0 {
		return raw
	}
	// Longest value first, so a value that contains another is folded before its
	// substring can shred it.
	names := make([]string, 0, len(vars))
	for name := range vars {
		if len(vars[name]) >= minCanonicalLen {
			names = append(names, name)
		}
	}
	sort.SliceStable(names, func(i, j int) bool { return len(vars[names[i]]) > len(vars[names[j]]) })

	out := raw
	for _, name := range names {
		out = bytes.ReplaceAll(out, []byte(vars[name]), []byte("{{"+name+"}}"))
	}
	return out
}

// minCanonicalLen keeps a short bound value from folding unrelated text. A
// two-character value occurs everywhere; replacing it would destroy the very
// differences this exists to preserve.
const minCanonicalLen = 6

// MethodOf reads a recorded request's method, for the safety gate and for labels.
func MethodOf(raw []byte) string {
	line, _, _ := strings.Cut(string(raw), "\n")
	method, _, _, ok := splitRequestLine(line)
	if !ok {
		return ""
	}
	return method
}

// TargetOf reads a recorded request's target, for labels.
func TargetOf(raw []byte) string {
	line, _, _ := strings.Cut(string(raw), "\n")
	_, target, _, ok := splitRequestLine(line)
	if !ok {
		return ""
	}
	return target
}

// splitRequestLine mirrors httptools.requestLine, which is unexported. Kept to
// three tokens by the same rule: the target may contain spaces in a malformed
// capture, so the first field is the method and the last the version.
func splitRequestLine(line string) (method, target, version string, ok bool) {
	parts := strings.Split(strings.TrimRight(line, "\r"), " ")
	if len(parts) < 3 {
		return "", "", "", false
	}
	return parts[0], strings.Join(parts[1:len(parts)-1], " "), parts[len(parts)-1], true
}

// Label renders a step's default display name.
func Label(raw []byte) string {
	m, t := MethodOf(raw), TargetOf(raw)
	if m == "" {
		return "(unparsable request)"
	}
	if i := strings.IndexByte(t, '?'); i > 0 {
		t = t[:i]
	}
	return m + " " + truncate(t, 48)
}
