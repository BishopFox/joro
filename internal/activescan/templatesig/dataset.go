package templatesig

import (
	_ "embed"
	"encoding/json"
	"regexp"
)

// signaturesJSON is the normalized, curated check set produced at design time by
// tools/nucleigen from a reviewed nuclei-templates checkout. It is embedded data,
// not a Go dependency; the server never parses a nuclei YAML template.
//
//go:embed signatures.json
var signaturesJSON []byte

// load parses and compiles the embedded dataset once, on the Rule instance (not a
// package global, per the no-globals rule). A signature whose regex will not
// compile under RE2 is dropped whole rather than run half-blind.
func (r *Rule) load() ([]Signature, error) {
	r.once.Do(func() {
		var sigs []Signature
		if err := json.Unmarshal(signaturesJSON, &sigs); err != nil {
			r.err = err
			return
		}
		out := make([]Signature, 0, len(sigs))
		for i := range sigs {
			if compileSignature(&sigs[i]) {
				out = append(out, sigs[i])
			}
		}
		r.sigs = out
	})
	return r.sigs, r.err
}

// compileSignature compiles every regex matcher in a signature. It returns false
// if any regex is rejected by RE2, so the caller can drop the whole check.
func compileSignature(sig *Signature) bool {
	for ri := range sig.Requests {
		req := &sig.Requests[ri]
		for mi := range req.Matchers {
			m := &req.Matchers[mi]
			if m.Type != "regex" {
				continue
			}
			m.compiled = m.compiled[:0]
			for _, expr := range m.Regexes {
				re, err := regexp.Compile(expr)
				if err != nil {
					return false
				}
				m.compiled = append(m.compiled, re)
			}
		}
	}
	return true
}
