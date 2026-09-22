package apispec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeDocument turns raw spec bytes into a generic document tree.
//
// # Three conditions hold this together; changing any one removes a protection
//
// First, JSON is decoded as JSON. If the first non-space byte is '{' this uses
// encoding/json, which is stricter, faster, and structurally immune to alias
// bombs because JSON has no aliases. Most real documents are JSON, so this takes
// the whole billion-laughs class off the table for the common case.
//
// Second, YAML is decoded INTO A VALUE, never into a yaml.Node. yaml.v3's
// billion-laughs guard lives in the decode path: it counts decodeCount and
// aliasCount while unmarshalling into a value and rejects a document whose alias
// ratio is too high for its size. A yaml.Node keeps aliases unexpanded, so
// walking one yourself bypasses the guard entirely. "Let's decode into a Node so
// diagnostics can carry line numbers" is the reasonable-looking change that
// would silently remove it — take the line numbers from somewhere else.
//
// Third, the guard is a ratio and not a memory cap, so a large document can pass
// it and still expand. countNodes bounds the decoded result afterwards.
//
// Two decode details beyond the guard. yaml.Unmarshal recovers only its own
// error type, so anything else panics out into the caller — hence the recover,
// which is load-bearing and not defensive habit. And duplicate mapping keys come
// back as a *yaml.TypeError while still producing a usable document; real
// documents have them, so they become diagnostics rather than a rejection.
func decodeDocument(data []byte) (map[string]any, []Diagnostic, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("document is empty")
	}
	if len(data) > MaxSpecBytes {
		return nil, nil, fmt.Errorf("document is %d bytes, over the %d-byte limit", len(data), MaxSpecBytes)
	}

	trimmed := bytes.TrimLeft(data, " \t\r\n\uFEFF")
	if len(trimmed) == 0 {
		return nil, nil, fmt.Errorf("document is empty")
	}

	var diags []Diagnostic

	if trimmed[0] == '{' {
		var doc map[string]any
		if err := json.Unmarshal(trimmed, &doc); err == nil {
			if n := countNodes(doc, 0); n > MaxDocNodes {
				return nil, nil, fmt.Errorf("document expands to %d nodes, over the %d-node limit", n, MaxDocNodes)
			}
			return doc, diags, nil
		}
		// Fall through: a document that starts with '{' but is not valid JSON may
		// still be valid YAML flow mapping.
	}

	doc, yamlDiags, err := decodeYAML(trimmed)
	if err != nil {
		return nil, nil, err
	}
	diags = append(diags, yamlDiags...)

	if n := countNodes(doc, 0); n > MaxDocNodes {
		return nil, nil, fmt.Errorf("document expands to %d nodes, over the %d-node limit", n, MaxDocNodes)
	}
	return doc, diags, nil
}

// decodeYAML unmarshals into a value so yaml.v3's alias guard applies, and
// converts a duplicate-key TypeError into diagnostics instead of an error.
func decodeYAML(data []byte) (doc map[string]any, diags []Diagnostic, err error) {
	defer func() {
		// yaml.Unmarshal's own handleErr recovers only yamlError; a malformed
		// document can panic through it, and a panic here would take down the
		// whole process for one bad file fetched from a target.
		if r := recover(); r != nil {
			doc, diags, err = nil, nil, fmt.Errorf("document could not be parsed as YAML: %v", r)
		}
	}()

	var raw map[string]any
	uerr := yaml.Unmarshal(data, &raw)
	if uerr != nil {
		var typeErr *yaml.TypeError
		if !errors.As(uerr, &typeErr) {
			return nil, nil, fmt.Errorf("document could not be parsed: %w", uerr)
		}
		// A TypeError still yields a usable document. Every message becomes a
		// diagnostic; duplicate keys are common enough in hand-written specs that
		// rejecting the file over them would be useless strictness.
		for _, msg := range typeErr.Errors {
			kind := DiagMalformed
			if strings.Contains(msg, "already set in map") || strings.Contains(msg, "duplicate") {
				kind = DiagDuplicateKey
			}
			diags = append(diags, Diagnostic{Kind: kind, Detail: msg})
		}
	}
	if raw == nil {
		return nil, nil, fmt.Errorf("document did not decode to an object")
	}

	// yaml.v3 decodes nested mappings as map[string]any when every key is a
	// string, but yields map[any]any otherwise. Normalize so the rest of the
	// package only ever sees one shape.
	normalized, ok := normalizeMaps(raw).(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("document did not decode to an object")
	}
	return normalized, diags, nil
}

// normalizeMaps rewrites map[any]any into map[string]any recursively, dropping
// any key that is not representable as a string. A non-string key cannot be
// addressed by a JSON pointer, so nothing downstream could reach it anyway.
func normalizeMaps(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalizeMaps(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			out[ks] = normalizeMaps(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalizeMaps(val)
		}
		return out
	default:
		return v
	}
}

// countNodes bounds the decoded document. It stops early once the budget is
// blown, so a document that did expand enormously is not walked in full.
func countNodes(v any, depth int) int {
	if depth > 512 {
		return MaxDocNodes + 1
	}
	switch t := v.(type) {
	case map[string]any:
		n := 1
		for _, val := range t {
			n += countNodes(val, depth+1)
			if n > MaxDocNodes {
				return n
			}
		}
		return n
	case []any:
		n := 1
		for _, val := range t {
			n += countNodes(val, depth+1)
			if n > MaxDocNodes {
				return n
			}
		}
		return n
	default:
		return 1
	}
}

// jsSpecAssignRe matches the "var spec = {...};" form a Swagger UI initializer
// uses. Swagger UI bundles serve the document wrapped in JavaScript, and an
// operator who found swagger-ui-init.js has found the document.
var jsSpecAssignRe = regexp.MustCompile(`(?s)(?:let|const|var)\s+\w+\s*=\s*(\{.*?\})\s*;`)

// UnwrapJSSpec extracts an API document embedded in a JavaScript file, reporting
// whether it found one. Input that is not JavaScript is returned unchanged, so
// this is safe to call on every candidate.
func UnwrapJSSpec(body []byte) ([]byte, bool) {
	for _, m := range jsSpecAssignRe.FindAllSubmatch(body, 16) {
		if len(m) < 2 {
			continue
		}
		candidate := m[1]
		if looksLikeSpecJSON(candidate) {
			return candidate, true
		}
		// swagger-ui-init.js nests the document under a wrapper key.
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(candidate, &wrapper); err != nil {
			continue
		}
		for _, key := range []string{"swaggerDoc", "spec", "openapi", "swagger"} {
			if inner, ok := wrapper[key]; ok && looksLikeSpecJSON(inner) {
				return inner, true
			}
		}
	}
	return body, false
}

// looksLikeSpecJSON reports whether bytes parse as an object carrying a version
// token and a paths member.
func looksLikeSpecJSON(b []byte) bool {
	var probe struct {
		Swagger string          `json:"swagger"`
		OpenAPI string          `json:"openapi"`
		Paths   json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return false
	}
	if len(probe.Paths) == 0 {
		return false
	}
	return strings.HasPrefix(probe.Swagger, "2") || strings.HasPrefix(probe.OpenAPI, "3")
}
