package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/proxy"
)

// sitemapArgs mirrors the history filter, since Store.Sitemap takes the same type.
type sitemapArgs struct {
	Host        string `json:"host"`
	Method      string `json:"method"`
	Status      string `json:"status"`
	ContentType string `json:"contentType"`
	Exclude     string `json:"exclude"`
	ExtMode     string `json:"extMode"`
	ScopeOnly   bool   `json:"scopeOnly"`
	MaxPaths    int    `json:"maxPaths"`
}

func registerSitemap(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "sitemap.get",
		Class: capability.ClassSitemap,
		Title: "Get the discovered site map",
		Description: "The set of origins and paths seen in captured traffic, with the methods observed and " +
			"the query parameter names for each. Built from real traffic, so it reflects what the target " +
			"actually served rather than a crawl. Requests that returned 404 are excluded.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":        {"type":"string","description":"Case-insensitive substring of the host, e.g. \"acme\"."},
    "method":      {"type":"string","description":"Comma-separated methods."},
    "status":      {"type":"string","description":"Status expression, e.g. \"2xx,3xx\"."},
    "contentType": {"type":"string","description":"Content-type keywords, comma-separated."},
    "exclude":     {"type":"string","description":"Comma-separated file extensions to exclude."},
    "extMode":     {"type":"string","enum":["exclude","include"]},
    "scopeOnly":   {"type":"boolean","description":"Restrict to requests matching Joro's configured scope."},
    "maxPaths":    {"type":"integer","minimum":1,"maximum":1000,"description":"Cap on paths returned per host; default 200."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"scopeOnly":true}`),
		MaxOutputBytes: 256 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args sitemapArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			f := proxy.RequestFilter{
				Host: args.Host, Method: args.Method, Status: args.Status,
				ContentType: args.ContentType, Exclude: args.Exclude,
				ExtMode: orDefault(args.ExtMode, "exclude"),
			}
			if args.ScopeOnly && d.Scope != nil {
				f.InScopeFunc = d.Scope.InScope
			}
			return renderSitemap(d.Store.Sitemap(f), args.MaxPaths), nil
		}),
	})
}

func registerScope(r *capability.Registry, d Deps) {
	// Read-only by construction. There is deliberately no scope.add_rule and there
	// never will be: scope is the safety control the send guard depends on, so an
	// agent that could widen it would have no leash at all. capability.Register
	// panics on a mutating scope-class capability, so this is enforced rather than
	// merely intended.
	r.MustRegister(capability.Capability{
		ID:    "scope.get",
		Class: capability.ClassScope,
		Title: "Read the configured scope",
		Description: "Joro's scope rules and whether scope is enabled. Worth reading before any send: when " +
			"a token requires scope, a send to a host that does not match an include rule is refused.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Scope == nil {
				return nil, fmt.Errorf("scope is unavailable")
			}
			var b strings.Builder
			fmt.Fprintf(&b, "enabled=%t rules=%d\n", d.Scope.IsEnabled(), d.Scope.RuleCount())
			if !d.Scope.IsEnabled() {
				b.WriteString("note: scope is disabled, so nothing is filtered and nothing is in scope for a scope-requiring token\n")
			}
			for _, rule := range d.Scope.Rules() {
				kind := "exclude"
				if rule.Include {
					kind = "include"
				}
				methods := "*"
				if len(rule.Methods) > 0 {
					methods = strings.Join(rule.Methods, ",")
				}
				fmt.Fprintf(&b, "%-7s host=%s methods=%s path=%s\n", kind, rule.Pattern, methods, orDefault(rule.Path, "*"))
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})
}

type findingsListArgs struct {
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Host       string `json:"host"`
	RuleID     string `json:"ruleId"`
	Search     string `json:"search"`
	Confidence string `json:"confidence"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
}

type findingsGetArgs struct {
	ID string `json:"id"`
}

func registerFindings(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "findings.list",
		Class: capability.ClassFindings,
		Title: "List passive detection findings",
		Description: "Findings from Joro's passive detection engine, as a compact table. Evidence is returned " +
			"redacted, exactly as the UI renders it; use findings_get for one finding's detail. " +
			"Info-severity findings are included only when severity explicitly asks for them.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "severity":   {"type":"string","description":"Comma-separated severities to include: critical, high, medium, low, info. Omit for everything above info."},
    "category":   {"type":"string","description":"Comma-separated categories."},
    "host":       {"type":"string","description":"Case-insensitive substring of the host, e.g. \"acme\"."},
    "ruleId":     {"type":"string","description":"Restrict to one rule."},
    "search":     {"type":"string","description":"Substring of the rule name, host or URL."},
    "confidence": {"type":"string","description":"Restrict to one confidence level."},
    "offset":     {"type":"integer","minimum":0},
    "limit":      {"type":"integer","minimum":1,"maximum":200,"description":"Rows to return; default 50."}
  },
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"severity":"critical,high","limit":25}`),
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args findingsListArgs) (any, error) {
			if d.Findings == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			f := detect.FindingFilter{
				Categories: splitCSV(args.Category),
				RuleID:     args.RuleID,
				Host:       args.Host,
				Search:     args.Search,
				Confidence: args.Confidence,
				Offset:     args.Offset,
				Limit:      clampInt(args.Limit, 50, 1, 200),
			}
			if sev := splitCSV(args.Severity); len(sev) > 0 {
				f.Severities = sev
			} else {
				// Match the UI's default: 233 of the 242 shipped rules are Info,
				// so including them unasked would bury everything else.
				f.Severities = []string{"critical", "high", "medium", "low"}
			}
			items, total := d.Findings.List(f, ruleEnabledFunc(d))
			return renderFindings(items, total, f.Offset), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:          "findings.get",
		Class:       capability.ClassFindings,
		Title:       "Get one finding",
		Description: "Full detail for a single finding, including its rule, target, evidence offset and any operator notes. Evidence remains redacted.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"id":{"type":"string","description":"Finding ID, as returned by findings_list."}},
  "required":["id"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"id":"a1b2c3d4e5f60718"}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args findingsGetArgs) (any, error) {
			if d.Findings == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			f, ok := d.Findings.Get(args.ID)
			if !ok {
				return nil, fmt.Errorf("no finding with id %s", args.ID)
			}
			return map[string]any{
				"id": f.ID, "rule": f.RuleID, "ruleName": f.RuleName,
				"severity": f.Severity, "confidence": f.Confidence, "category": f.Category,
				"host": f.Host, "method": f.Method, "url": f.URL,
				"detail": f.Detail, "evidence": f.Evidence,
				"evidencePart": f.EvidencePart, "evidenceOffset": f.EvidenceOffset,
				"evidenceLength": f.EvidenceLength,
				"count":          f.Count, "firstSeen": f.FirstSeen, "lastSeen": f.LastSeen,
				"falsePositive": f.FalsePositive, "notes": f.Notes,
			}, nil
		}),
	})
}

type notesListArgs struct {
	Host   string `json:"host"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}

func registerNotes(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "notes.list",
		Class: capability.ClassNotes,
		Title: "Read engagement notes",
		Description: "The operator's notes for this engagement, optionally filtered to one host. Useful for " +
			"picking up context the operator has already established. Read-only: notes are the operator's record.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":   {"type":"string","description":"Host to filter to. An empty host selects the host-less \"General\" bucket."},
    "offset": {"type":"integer","minimum":0},
    "limit":  {"type":"integer","minimum":1,"maximum":200,"description":"Notes to return; default 50."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"limit":20}`),
		MaxOutputBytes: 256 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args notesListArgs) (any, error) {
			if d.Notes == nil {
				return nil, fmt.Errorf("notes are unavailable")
			}
			items, total, err := d.Notes.ListNotes(args.Host, args.Offset, clampInt(args.Limit, 50, 1, 200))
			if err != nil {
				return nil, err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "n=%d/%d\n", len(items), total)
			for _, n := range items {
				fmt.Fprintf(&b, "--- %s %s (%s)\n%s\n", n.CreatedAt.UTC().Format("2006-01-02 15:04"), orDefault(n.Host, "General"), n.Author, n.Content)
			}
			if len(items) == 0 {
				return "(no notes)", nil
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})
}

func ruleEnabledFunc(d Deps) func(string) bool {
	if d.Engine == nil {
		return func(string) bool { return true }
	}
	return d.Engine.RuleEnabledFunc()
}
