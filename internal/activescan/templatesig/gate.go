package templatesig

import (
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
)

// selectSignatures narrows the dataset to what should run against one host: the
// scan's tag/severity filters, then fingerprint gating.
//
// Gating runs a signature when it is tech-agnostic (no RequiresTech) or when one
// of its required technologies is present on the host, version permitting. With
// IgnoreFingerprint set, or no fingerprint store wired, gating is skipped and
// every tag/severity-passing signature runs. When the host has a fingerprint but
// nothing was detected, only tech-agnostic signatures run.
func selectSignatures(sigs []Signature, cfg activescan.Config, deps activescan.RuleDeps, host string, disabled *activescan.DisabledSet) []Signature {
	tagFilter := lowerSet(cfg.Tags)
	sevFilter := lowerSet(cfg.Severity)

	gate := !cfg.IgnoreFingerprint && deps.Tech != nil
	var detected map[string]string // lower tech name -> version ("" if unknown)
	if gate {
		detected = map[string]string{}
		if ht, ok := deps.Tech.Host(host); ok {
			for _, t := range ht.Technologies {
				detected[strings.ToLower(t.Name)] = t.Version
			}
		}
	}

	out := make([]Signature, 0, len(sigs))
	for _, sig := range sigs {
		if !disabled.IsItemEnabled(sig.ID) {
			continue
		}
		if len(tagFilter) > 0 && !anyIn(sig.Tags, tagFilter) {
			continue
		}
		if len(sevFilter) > 0 && !sevFilter[strings.ToLower(sig.Severity)] {
			continue
		}
		if gate && !eligible(sig, detected) {
			continue
		}
		out = append(out, sig)
	}
	return out
}

// eligible reports whether a signature's technology preconditions are met.
func eligible(sig Signature, detected map[string]string) bool {
	if len(sig.RequiresTech) == 0 {
		return true
	}
	for _, req := range sig.RequiresTech {
		ver, ok := detected[strings.ToLower(req.Name)]
		if ok && versionOK(ver, req) {
			return true
		}
	}
	return false
}

// versionOK applies a version constraint, failing open on an unknown version: a
// detected-but-unversioned technology always satisfies the bound, because
// skipping a possibly-vulnerable host is worse than an occasional wasted probe.
func versionOK(detected string, req TechReq) bool {
	if detected == "" {
		return true
	}
	if req.MinVersion != "" && compareVersion(detected, req.MinVersion) < 0 {
		return false
	}
	if req.MaxVersion != "" && compareVersion(detected, req.MaxVersion) >= 0 {
		return false
	}
	return true
}

// compareVersion compares dotted numeric versions, returning -1, 0 or 1. A
// non-numeric segment compares as 0, which is lenient by design.
func compareVersion(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(numeric(as[i]))
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(numeric(bs[i]))
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// numeric keeps the leading digit run of a version segment ("4rc1" -> "4").
func numeric(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

func lowerSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out[s] = true
		}
	}
	return out
}

func anyIn(vals []string, set map[string]bool) bool {
	for _, v := range vals {
		if set[strings.ToLower(v)] {
			return true
		}
	}
	return false
}
