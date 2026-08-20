package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// decodeArgs is the one place automation arguments become a Go value. Typed and
// TypedTarget both route through it so the guidance on a misnamed field is identical
// whether the client got it wrong in a handler's arguments or in the arguments the
// scope guard reads.
//
// On error the returned value is partially populated; both callers return
// immediately rather than inspect it.
func decodeArgs[T any](raw json.RawMessage) (T, error) {
	var args T
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return args, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&args); err != nil {
		return args, &Error{Code: CodeInvalidArgs, Msg: decodeMsg(err, reflect.TypeFor[T]())}
	}
	return args, nil
}

// decodeMsg rewrites a decode failure into something a model can act on. Only the
// unknown-field case is rewritten; every other failure, a type mismatch above all,
// passes through untouched.
//
// A near miss earns a suggestion and nothing else does. The accepted names are not
// enumerated on a miss, because every capability publishes a complete InputSchema
// with additionalProperties:false — the caller already holds the list, so printing
// it again costs tokens on every error and tells it nothing new.
func decodeMsg(err error, t reflect.Type) string {
	field, ok := unknownField(err.Error())
	if !ok {
		return err.Error()
	}
	if best, ok := nearest(field, fieldCandidates(t, 0)); ok {
		return fmt.Sprintf("unknown field %q — did you mean %q?", field, best)
	}
	return fmt.Sprintf("unknown field %q", field)
}

const unknownFieldPrefix = "json: unknown field "

// unknownField recovers the offending name from encoding/json's unknown-field error.
// That error is a bare fmt.Errorf with no wrapping and no exported type, so matching
// its text is the only handle there is. The text is identical in the v1 decoder and
// in the v2 compatibility shim, both of which format it with %q, so this holds
// whether or not GOEXPERIMENT=jsonv2 is set.
//
// strconv.Unquote is the exact inverse of that %q, and it fails on trailing content,
// so a longer message that merely starts the same way cannot match by accident.
func unknownField(msg string) (string, bool) {
	q, ok := strings.CutPrefix(msg, unknownFieldPrefix)
	if !ok {
		return "", false
	}
	name, err := strconv.Unquote(q)
	if err != nil || name == "" {
		return "", false
	}
	return name, true
}

// maxAliasDepth bounds the struct walk. Reflect types cycle only through pointers,
// which the walk does not follow past a struct boundary, so a depth cap terminates
// where a visited set would and costs nothing to read.
const maxAliasDepth = 3

// candidate is one name the client's field is measured against, and the name to
// suggest when it wins. The two differ only for an alias, where a former name is
// matched but the field that replaced it is what gets named.
type candidate struct{ match, suggest string }

// fieldCandidates lists the names a decode of t will accept, by the same rules
// encoding/json applies: the tag name when tagged, the Go field name otherwise,
// `json:"-"` skipped, anonymous structs flattened. An `alias` tag adds a name that
// is matched but not accepted — see the alias rule on nearest.
//
// The anonymous check must precede the exported check. An embedded field of an
// unexported type reads as unexported through IsExported, yet the decoder still
// promotes its exported fields; scriptReplaceArgs in internal/capreg is exactly that
// shape, and reversing the two would silently empty its candidate list.
func fieldCandidates(t reflect.Type, depth int) []candidate {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || depth > maxAliasDepth {
		return nil
	}
	var out []candidate
	add := func(c candidate) {
		// Deduping is load-bearing: a name promoted twice would rank as its own
		// second best and trip the tie guard in nearest.
		if c.match == "" || slices.ContainsFunc(out, func(o candidate) bool { return o.match == c.match }) {
			return
		}
		out = append(out, c)
	}
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		// The whole tag, not the parsed name: `json:"-,"` legitimately names a field "-".
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			for _, c := range fieldCandidates(f.Type, depth+1) {
				add(c)
			}
			continue
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		add(candidate{match: name, suggest: name})
		add(candidate{match: f.Tag.Get("alias"), suggest: name})
	}
	return out
}

// nearest names the one field closest to what the client sent, or reports that
// nothing is close enough.
//
// The distance is computed after folding case and dropping separators, so a client
// writing max_matches or MaxMatches lands on maxMatches at distance zero. The case
// half of that is belt and braces — DisallowUnknownFields already matches names
// case-insensitively, so contenttype never reaches here — and the separator half is
// the part doing real work.
//
// An alias resolves to the field it is declared on, so a name that is no longer
// accepted can still point at the one that replaced it. This is the only way a
// suggestion crosses a semantic gap: string distance cannot, and a threshold loosened
// far enough to bridge one would suggest a match for nearly every short key. Declare
// an alias rather than widening the limit.
func nearest(unknown string, candidates []candidate) (string, bool) {
	want := normalizeName(unknown)
	// Scaled to the input's length: one edit is most of a short word and very little
	// of a long one. Two characters or fewer admit exact matches only, which is what
	// keeps a stray single-character key from drawing a coin flip between http.diff's
	// "a" and "b".
	limit := 2
	switch {
	case len(want) <= 2:
		limit = 0
	case len(want) <= 5:
		limit = 1
	}

	best, second, bestD, secondD := "", "", limit+1, limit+1
	for _, c := range candidates {
		d := editDistance(want, normalizeName(c.match))
		switch {
		case d < bestD:
			best, second, secondD, bestD = c.suggest, best, bestD, d
		case d < secondD:
			second, secondD = c.suggest, d
		}
	}
	// A tie is two equally good answers, which is no answer: saying nothing beats
	// sending a model confidently to the wrong field. Two names that resolve to the
	// same field — a field and its own alias — are one answer, not a tie.
	if bestD > limit || (bestD == secondD && best != second) {
		return "", false
	}
	return best, true
}

// normalizeName folds a field name to the form the distance is measured on: ASCII
// lowercase with the separators that distinguish naming conventions removed.
func normalizeName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '_', '-', '.', ' ':
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// editDistance is Levenshtein over two rows.
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len([]rune(b))
	}
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			sub := prev[j-1]
			if ra[i-1] != rb[j-1] {
				sub++
			}
			curr[j] = min(sub, prev[j]+1, curr[j-1]+1)
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}
