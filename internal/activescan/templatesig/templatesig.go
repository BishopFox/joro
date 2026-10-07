// Package templatesig is the active-scan signature rule: it sends crafted HTTP
// requests and files a finding when the response matches a check. The checks are
// an embedded, normalized dataset mined at design time from nuclei-templates (see
// tools/nucleigen) — the server never parses a nuclei YAML template, only this
// vetted schema.
//
// # Fingerprint-gated
//
// Before sending, the rule reads the passive technology fingerprint of the host
// (internal/techfp) and runs only the signatures whose RequiresTech matches the
// detected stack, plus the tech-agnostic ones. A WordPress host is probed for
// WordPress and PHP checks, not for Jira or Drupal ones. Gating is version-aware
// but fail-open: a version constraint narrows only when the version is known.
//
// # Fail-closed at the source, not here
//
// The matcher vocabulary is deliberately small (status, word, regex, size, with
// and/or and negation). That is not a runtime limitation to work around: the
// converter emits a signature only when a template's whole logic fits this
// vocabulary, and drops the rest. So a signature that reaches this package is one
// Joro can evaluate faithfully — there is no partial evaluation that could report
// a vulnerable target as safe.
package templatesig

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/httptools"
)

const (
	ruleID      = "templatesig"
	findingRule = "activescan.templatesig"

	perRequestTimeout = 15 * time.Second
	// maxRespBytes is the response body a match needs; the send default is sized
	// only to fingerprint, which is too little for a body word/regex matcher.
	maxRespBytes = 1 << 20
)

// TechReq is a technology precondition on a signature. An empty Name list on a
// signature means tech-agnostic (always eligible). MinVersion is inclusive,
// MaxVersion exclusive; either may be empty.
type TechReq struct {
	Name       string `json:"name"`
	MinVersion string `json:"minVersion,omitempty"`
	MaxVersion string `json:"maxVersion,omitempty"`
}

// Matcher is one condition evaluated against a response.
type Matcher struct {
	Type      string   `json:"type"`           // status | word | regex | size
	Part      string   `json:"part,omitempty"` // body | header | all (default body)
	Status    []int    `json:"status,omitempty"`
	Words     []string `json:"words,omitempty"`
	Regexes   []string `json:"regexes,omitempty"`
	Sizes     []int    `json:"sizes,omitempty"`
	Condition string   `json:"condition,omitempty"` // and | or across words/regexes (default or)
	Negative  bool     `json:"negative,omitempty"`

	compiled []*regexp.Regexp // filled by compile()
}

// Request is one probe: a method and one or more paths sharing a matcher set.
type Request struct {
	Method            string            `json:"method"`
	Paths             []string          `json:"paths"` // {{BaseURL}}-relative, e.g. "/.git/config"
	Headers           map[string]string `json:"headers,omitempty"`
	Body              string            `json:"body,omitempty"`
	Matchers          []Matcher         `json:"matchers"`
	MatchersCondition string            `json:"matchersCondition,omitempty"` // and | or (default or)
	StopAtFirstMatch  bool              `json:"stopAtFirstMatch,omitempty"`
}

// Signature is one normalized check mined from a nuclei template.
type Signature struct {
	ID           string    `json:"id"`
	NucleiID     string    `json:"nucleiId,omitempty"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"`
	Description  string    `json:"description,omitempty"`
	Remediation  string    `json:"remediation,omitempty"`
	Reference    []string  `json:"reference,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	Source       string    `json:"source,omitempty"`
	RequiresTech []TechReq `json:"requiresTech,omitempty"`
	Requests     []Request `json:"requests"`
}

// Rule implements activescan.Rule and activescan.Cataloger over the embedded
// signature set. The per-signature enable/disable half of Cataloger comes from the
// embedded *activescan.DisabledSet (per-project session state set by
// applyProjectConfig and read by buildProjectConfig).
type Rule struct {
	once sync.Once
	sigs []Signature
	err  error
	*activescan.DisabledSet
}

// New returns the template-signature rule. The embedded dataset is parsed and its
// regexes compiled lazily on first Run, off the server boot path.
func New() *Rule { return &Rule{DisabledSet: activescan.NewDisabledSet()} }

// RuleID is the stable registry id of this rule, for callers that resolve the
// concrete rule from the registry.
func RuleID() string { return ruleID }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "Template signatures" }
func (*Rule) Category() detect.Category { return detect.CategoryTemplate }

func (*Rule) Description() string {
	return "HTTP request signatures mined from nuclei templates — exposed files, " +
		"known-vulnerable fingerprints, misconfigurations, and exposed panels. Fingerprint-" +
		"gated: only signatures matching a host's detected technology stack run, plus the " +
		"tech-agnostic ones."
}

// CatalogItems maps each loaded signature to a neutral catalog item for the UI.
func (r *Rule) CatalogItems() []activescan.CatalogItem {
	sigs, err := r.load()
	if err != nil {
		return nil
	}
	out := make([]activescan.CatalogItem, 0, len(sigs))
	for i := range sigs {
		sig := &sigs[i]
		var method string
		var paths []string
		if len(sig.Requests) > 0 {
			method = sig.Requests[0].Method
			paths = sig.Requests[0].Paths
		}
		tech := make([]string, 0, len(sig.RequiresTech))
		for _, t := range sig.RequiresTech {
			tech = append(tech, t.Name)
		}
		detail := []activescan.CatalogField{}
		add := func(label, value string) {
			if value != "" {
				detail = append(detail, activescan.CatalogField{Label: label, Value: value})
			}
		}
		if method != "" || len(paths) > 0 {
			add("Request", strings.TrimSpace(method+" "+strings.Join(paths, ", ")))
		}
		add("Required technology", strings.Join(tech, ", "))
		add("Tags", strings.Join(sig.Tags, ", "))
		add("References", strings.Join(sig.Reference, "\n"))
		add("Nuclei ID", sig.NucleiID)
		add("Source", sig.Source)
		out = append(out, activescan.CatalogItem{
			ID:          sig.ID,
			Name:        sig.Name,
			Severity:    sig.Severity,
			Confidence:  string(sig.Confidence()),
			Target:      string(detect.TargetMessage),
			Description: sig.Description,
			Remediation: sig.Remediation,
			Enabled:     r.IsItemEnabled(sig.ID),
			Detail:      detail,
		})
	}
	return out
}

// Run selects the eligible signatures for the target's technology stack and
// probes each, filing a finding per confirmed match.
func (r *Rule) Run(ctx context.Context, t activescan.Target, cfg activescan.Config, deps activescan.RuleDeps, rep activescan.Reporter) error {
	sigs, err := r.load()
	if err != nil {
		return fmt.Errorf("load signatures: %w", err)
	}

	selected := selectSignatures(sigs, cfg, deps, t.Host, r.DisabledSet)
	prog := newSpreader(rep, len(t.URLs), len(selected))
	defer prog.finish()

	send := httptools.SendDeps{
		ProxyAddr:    deps.ProxyAddr,
		CA:           deps.CA,
		Store:        deps.Store,
		MaxRespBytes: maxRespBytes,
	}

	for _, sig := range selected {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.runSignature(ctx, t, sig, send, rep)
		prog.step()
	}
	return nil
}

// runSignature probes every request/path of one signature, stopping a request's
// path sweep at the first match when the signature asks for it.
func (r *Rule) runSignature(ctx context.Context, t activescan.Target, sig Signature, send httptools.SendDeps, rep activescan.Reporter) {
	for ri := range sig.Requests {
		req := &sig.Requests[ri]
		for _, path := range req.Paths {
			if ctx.Err() != nil {
				return
			}
			raw, err := renderRequest(t.Origin, req, path)
			if err != nil {
				continue
			}
			reqCtx, cancel := context.WithTimeout(ctx, perRequestTimeout)
			sent, err := httptools.SendViaProxy(reqCtx, raw, t.Scheme, t.Host, send)
			cancel()
			if err != nil {
				continue
			}
			resp := httptools.ReadResponse(sent.RespRaw)
			rp := replacer{baseURL: strings.TrimRight(t.Origin, "/"), host: t.Host}
			ok, evidence := evalMatchers(req, resp, rp)
			if !ok {
				continue
			}
			rep.Finding(buildFinding(t.Host, t.Origin, path, sent.URL, sig, evidence))
			if req.StopAtFirstMatch {
				break
			}
		}
	}
}

// buildFinding maps a confirmed match to a detect.Finding in detect's identity
// space, deduped per signature, host and path.
func buildFinding(host, origin, path, sentURL string, sig Signature, evidence string) detect.Finding {
	now := time.Now()
	u := sentURL
	if u == "" {
		u = strings.TrimRight(origin, "/") + path
	}
	detail := sig.Name
	if sig.NucleiID != "" {
		detail = sig.NucleiID + ": " + sig.Name
	}
	return detect.Finding{
		ID:             detect.FindingID(sig.ID, host, path),
		RuleID:         findingRule,
		RuleName:       sig.Name,
		Category:       detect.CategoryTemplate,
		Severity:       mapSeverity(sig.Severity),
		Confidence:     confidenceFor(sig),
		Target:         detect.TargetMessage,
		Host:           host,
		Method:         requestMethod(sig),
		URL:            u,
		Detail:         detail,
		Evidence:       evidence,
		FirstSeen:      now,
		LastSeen:       now,
		EvidenceOffset: -1,
	}
}

func requestMethod(sig Signature) string {
	if len(sig.Requests) > 0 && sig.Requests[0].Method != "" {
		return strings.ToUpper(sig.Requests[0].Method)
	}
	return "GET"
}

// mapSeverity converts a nuclei severity string to a detect.Severity, defaulting
// to info for an unknown value.
func mapSeverity(s string) detect.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return detect.SeverityCritical
	case "high":
		return detect.SeverityHigh
	case "medium":
		return detect.SeverityMedium
	case "low":
		return detect.SeverityLow
	default:
		return detect.SeverityInfo
	}
}

// Confidence is the finding confidence a match of this signature carries, for the
// catalog UI. It is the same value buildFinding files.
func (sig Signature) Confidence() detect.Confidence { return confidenceFor(sig) }

// confidenceFor estimates confidence from matcher strength: a regex or a
// multi-term/status-qualified match is high; a lone word is medium; a bare status
// match is low. Nuclei carries no confidence of its own.
func confidenceFor(sig Signature) detect.Confidence {
	hasRegex, words, hasStatus, nonStatus := false, 0, false, false
	for _, req := range sig.Requests {
		for _, m := range req.Matchers {
			switch m.Type {
			case "regex":
				hasRegex = true
				nonStatus = true
			case "word":
				words += len(m.Words)
				nonStatus = true
			case "status":
				hasStatus = true
			case "size":
				nonStatus = true
			}
		}
	}
	switch {
	case hasRegex || (hasStatus && nonStatus) || words > 1:
		return detect.ConfidenceHigh
	case words == 1 || nonStatus:
		return detect.ConfidenceMedium
	default:
		return detect.ConfidenceLow
	}
}

// originPath splits an absolute URL into its path+query, for rendering.
func originPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return raw
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}
