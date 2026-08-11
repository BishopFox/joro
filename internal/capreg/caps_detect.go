package capreg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/detect"
)

// The detect class: the detection engine's rules, its configuration, and rescanning.
//
// Findings triage lives in the findings class instead (findings.list/get/update),
// because triaging results and changing what gets detected are different operator
// concerns and should be separately grantable — one reads a rule's output, the other
// changes every future scan.
//
// Built-ins are partly protected by the engine itself: AddRule/UpdateRule/RemoveRule
// return ErrBuiltinImmutable for a shipped rule, while SetRuleEnabled and
// SetRuleSeverity are allowed on one. That asymmetry is deliberate upstream — those
// two change the operator's view of a rule rather than the rule — and is passed
// through here rather than re-litigated.

const maxAgentDetectRules = 300

type detectRulesListArgs struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Search   string `json:"search"`
	Builtin  string `json:"builtin"`
	Enabled  string `json:"enabled"`
	Limit    int    `json:"limit"`
}

type detectRulesEditArgs struct {
	Op      string `json:"op"`
	ID      string `json:"id"`
	Enabled *bool  `json:"enabled"`

	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Pattern        string   `json:"pattern"`
	Literal        string   `json:"literal"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	Target         string   `json:"target"`
	CaptureGroup   int      `json:"captureGroup"`
	MinLength      int      `json:"minLength"`
	MinEntropy     float64  `json:"minEntropy"`
	ContentTypes   []string `json:"contentTypes"`
	GroupBy        string   `json:"groupBy"`
	RedactEvidence bool     `json:"redactEvidence"`
}

type detectConfigSetArgs struct {
	ScopeOnly                *bool     `json:"scopeOnly"`
	ScanRequests             *bool     `json:"scanRequests"`
	PersistFindings          *bool     `json:"persistFindings"`
	ClearFindingsWithHistory *bool     `json:"clearFindingsWithHistory"`
	MaxBodyScanBytes         *int      `json:"maxBodyScanBytes"`
	MaxRequestBodyScanBytes  *int      `json:"maxRequestBodyScanBytes"`
	ExcludeHosts             *[]string `json:"excludeHosts"`
}

type detectRescanArgs struct {
	Scope string `json:"scope"`
	Host  string `json:"host"`
}

func registerDetect(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "detect.rules.list",
		Class: capability.ClassDetect,
		Title: "List detection rules",
		Description: "Joro's passive detection rules, built-in and operator-defined, as a compact table. There " +
			"are well over a hundred, so filter rather than listing them all. Use this to find out why something " +
			"was or was not reported before concluding a target is clean — a disabled rule and an absent " +
			"finding look identical from findings_list.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "category": {"type":"string","description":"Comma-separated categories: secrets, pii, credentials, access, disclosure, headers, cookies."},
    "severity": {"type":"string","description":"Comma-separated severities: critical, high, medium, low, info."},
    "search":   {"type":"string","description":"Substring of the rule ID, name or description."},
    "builtin":  {"type":"string","enum":["true","false"],"description":"Restrict to built-in or to operator-defined rules."},
    "enabled":  {"type":"string","enum":["true","false"],"description":"Restrict to enabled or disabled rules."},
    "limit":    {"type":"integer","minimum":1,"maximum":300,"description":"Rows to return; default 100."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"category":"secrets","enabled":"true","limit":50}`),
		MaxOutputBytes: 128 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args detectRulesListArgs) (any, error) {
			if d.Engine == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			cats := splitCSV(strings.ToLower(args.Category))
			sevs := splitCSV(strings.ToLower(args.Severity))
			search := strings.ToLower(strings.TrimSpace(args.Search))
			limit := clampInt(args.Limit, 100, 1, 300)

			all := d.Engine.Rules()
			matched := make([]detect.Rule, 0, len(all))
			for _, rule := range all {
				switch {
				case len(cats) > 0 && !slices.Contains(cats, string(rule.Category)):
					continue
				case len(sevs) > 0 && !slices.Contains(sevs, string(rule.Severity)):
					continue
				case args.Builtin == "true" && !rule.Builtin, args.Builtin == "false" && rule.Builtin:
					continue
				case args.Enabled == "true" && !rule.Enabled, args.Enabled == "false" && rule.Enabled:
					continue
				case search != "" && !strings.Contains(strings.ToLower(rule.ID+" "+rule.Name+" "+rule.Description), search):
					continue
				}
				matched = append(matched, rule)
			}
			if len(matched) == 0 {
				return "(no rules matched)", nil
			}

			total := len(matched)
			truncated := false
			if len(matched) > limit {
				matched, truncated = matched[:limit], true
			}

			var b strings.Builder
			fmt.Fprintf(&b, "n=%d/%d\n", len(matched), total)
			widths := []int{0, 0, 0, 0}
			rows := make([][]string, 0, len(matched))
			for _, rule := range matched {
				flags := "on"
				if !rule.Enabled {
					flags = "off"
				}
				if !rule.Builtin {
					flags += ",user"
				}
				row := []string{rule.ID, string(rule.Severity), string(rule.Category), flags, rule.Name}
				for i := range widths {
					widths[i] = max(widths[i], len(row[i]))
				}
				rows = append(rows, row)
			}
			b.WriteString(pad("id", widths[0]) + " " + pad("sev", widths[1]) + " " +
				pad("category", widths[2]) + " " + pad("state", widths[3]) + " name\n")
			for _, row := range rows {
				fmt.Fprintf(&b, "%s %s %s %s %s\n", pad(row[0], widths[0]), pad(row[1], widths[1]),
					pad(row[2], widths[2]), pad(row[3], widths[3]), row[4])
			}
			if truncated {
				fmt.Fprintf(&b, "[%d more; narrow with category, severity or search]\n", total-len(matched))
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "detect.rules.edit",
		Class:    capability.ClassDetect,
		Title:    "Add, remove, enable or re-grade a detection rule",
		Mutating: true,
		Description: "Change the detection rule set: add a regex rule, remove one you added, toggle any rule, or " +
			"override any rule's severity. Adding a rule affects only traffic scanned from now on — call " +
			"detect_rescan to apply it to what is already captured. Built-in rules cannot be added to or " +
			"removed, but can be toggled and re-graded, because those change the operator's view rather than " +
			"the rule. A pattern is RE2: no lookahead, no lookbehind, no backreferences.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "op":       {"type":"string","enum":["add","remove","setenabled","setseverity"],"description":"Which operation to perform."},
    "id":       {"type":"string","description":"Rule ID. Required for remove, setenabled and setseverity."},
    "enabled":  {"type":"boolean","description":"setenabled only: the new state."},
    "name":     {"type":"string","description":"add only: rule name, sentence case, no trailing period, e.g. \"Internal API key exposed\"."},
    "description": {"type":"string","description":"add only: one line explaining what the rule finds. Required."},
    "pattern":  {"type":"string","description":"add only: the RE2 pattern."},
    "literal":  {"type":"string","description":"add only: a case-insensitive substring prescreen that must appear in EVERY string the pattern can match, or the rule silently never fires. Optional but a large performance win."},
    "category": {"type":"string","enum":["secrets","pii","credentials","access","disclosure","headers","cookies"],"description":"add only."},
    "severity": {"type":"string","enum":["critical","high","medium","low","info"],"description":"add: the rule's severity. setseverity: the override."},
    "confidence": {"type":"string","enum":["high","medium","low"],"description":"add only. Default medium."},
    "target":   {"type":"string","enum":["response_body","response_header","request_body","request_header","url"],"description":"add only: what the pattern runs against. Default response_body."},
    "captureGroup": {"type":"integer","minimum":0,"description":"add only: which submatch becomes the evidence. 0 means the whole match."},
    "minLength": {"type":"integer","minimum":0,"description":"add only: reject captures shorter than this."},
    "minEntropy": {"type":"number","minimum":0,"description":"add only: reject captures below this Shannon entropy in bits per character. Useful to avoid matching placeholders."},
    "contentTypes": {"type":"array","items":{"type":"string"},"description":"add only: restrict body rules to these content-type keywords (json, html, xml, csv, plain, js, css)."},
    "groupBy":  {"type":"string","enum":["evidence","url","host"],"description":"add only: dedupe mode. evidence gives one finding per distinct value, url one per path, host one per host. Default evidence."},
    "redactEvidence": {"type":"boolean","description":"add only: mask the middle of the matched value in the UI. Use for anything credential-shaped."}
  },
  "required":["op"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"op":"add","name":"Acme internal token exposed","description":"Acme-issued service token in a response body.",` +
			`"pattern":"acme_tok_[A-Za-z0-9]{32}","literal":"acme_tok_","category":"secrets","severity":"high","redactEvidence":true}`),
		MaxOutputBytes: 16 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args detectRulesEditArgs) (any, error) {
			if d.Engine == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			switch args.Op {
			case "add":
				return detectRuleAdd(ctx, d, args)

			case "remove":
				if args.ID == "" {
					return nil, fmt.Errorf("id is required to remove a rule")
				}
				if err := d.Engine.RemoveRule(args.ID); err != nil {
					return nil, describeRuleErr(err, args.ID)
				}
				capability.RecordChange(ctx, "remove detect rule %s", args.ID)
				broadcastDetectRules(d)
				return fmt.Sprintf("removed rule %s", args.ID), nil

			case "setenabled":
				if args.ID == "" {
					return nil, fmt.Errorf("id is required")
				}
				if args.Enabled == nil {
					return nil, fmt.Errorf("enabled is required for op setenabled")
				}
				if err := d.Engine.SetRuleEnabled(args.ID, *args.Enabled); err != nil {
					return nil, describeRuleErr(err, args.ID)
				}
				capability.RecordChange(ctx, "set detect rule %s enabled=%t", args.ID, *args.Enabled)
				broadcastDetectRules(d)
				return fmt.Sprintf("rule %s enabled=%t (active rules: %d)",
					args.ID, *args.Enabled, d.Engine.ActiveRuleCount()), nil

			case "setseverity":
				if args.ID == "" {
					return nil, fmt.Errorf("id is required")
				}
				sev := detect.Severity(args.Severity)
				if !sev.Valid() {
					return nil, fmt.Errorf("severity %q is not one of critical, high, medium, low, info", args.Severity)
				}
				if err := d.Engine.SetRuleSeverity(args.ID, sev); err != nil {
					return nil, describeRuleErr(err, args.ID)
				}
				capability.RecordChange(ctx, "set detect rule %s severity=%s", args.ID, sev)
				broadcastDetectRules(d)
				return fmt.Sprintf("rule %s severity=%s", args.ID, sev), nil
			}
			return nil, fmt.Errorf(`op must be one of "add", "remove", "setenabled", "setseverity"`)
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "detect.config.get",
		Class: capability.ClassDetect,
		Title: "Read detection configuration",
		Description: "Whether passive detection is enabled, its scanning limits, and what it skips. Read this " +
			"before trusting an empty findings list: detection may be off, restricted to in-scope traffic, or " +
			"skipping the content type you care about.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 32 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Engine == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			cfg := d.Engine.Config()
			var b strings.Builder
			fmt.Fprintf(&b, "enabled=%t activeRules=%d\n", d.Engine.IsEnabled(), d.Engine.ActiveRuleCount())
			fmt.Fprintf(&b, "scopeOnly=%t scanRequests=%t persistFindings=%t clearFindingsWithHistory=%t\n",
				cfg.ScopeOnly, cfg.ScanRequests, cfg.PersistFindings, cfg.ClearFindingsWithHistory)
			fmt.Fprintf(&b, "maxBodyScanBytes=%d maxRequestBodyScanBytes=%d\n",
				cfg.MaxBodyScanBytes, cfg.MaxRequestBodyScanBytes)
			fmt.Fprintf(&b, "skipContentTypes=%s\n", joinOr(cfg.SkipContentTypes, "(none)"))
			fmt.Fprintf(&b, "skipExtensions=%s\n", joinOr(cfg.SkipExtensions, "(none)"))
			fmt.Fprintf(&b, "excludeHosts=%s", joinOr(cfg.ExcludeHosts, "(none)"))
			return b.String(), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "detect.config.set",
		Class:    capability.ClassDetect,
		Title:    "Change detection configuration",
		Mutating: true,
		Description: "Patch the detection engine's configuration. Only the fields you supply change. Raising a " +
			"scan-size limit or clearing scopeOnly widens what is scanned but costs CPU on the proxy path. " +
			"skipContentTypes and skipExtensions are not settable here: their defaults encode reasoning about " +
			"what is opaque by design, such as encrypted OHTTP payloads.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "scopeOnly":                {"type":"boolean","description":"Limit scanning to in-scope requests."},
    "scanRequests":             {"type":"boolean","description":"Also scan request-side targets: Basic auth, credentials in query strings, keys the app posts."},
    "persistFindings":          {"type":"boolean","description":"Snapshot findings into the operator's project file."},
    "clearFindingsWithHistory": {"type":"boolean","description":"Clear findings whenever request history is cleared."},
    "maxBodyScanBytes":         {"type":"integer","minimum":1024,"maximum":16777216,"description":"Response body bytes scanned per message."},
    "maxRequestBodyScanBytes":  {"type":"integer","minimum":1024,"maximum":16777216,"description":"Request body bytes scanned per message."},
    "excludeHosts":             {"type":"array","items":{"type":"string"},"description":"Suppress findings whose host contains any of these substrings. Replaces the whole list."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"scanRequests":true,"scopeOnly":false}`),
		MaxOutputBytes: 32 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args detectConfigSetArgs) (any, error) {
			if d.Engine == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			cfg := d.Engine.Config()
			var changed []string
			if args.ScopeOnly != nil {
				cfg.ScopeOnly = *args.ScopeOnly
				changed = append(changed, fmt.Sprintf("scopeOnly=%t", *args.ScopeOnly))
			}
			if args.ScanRequests != nil {
				cfg.ScanRequests = *args.ScanRequests
				changed = append(changed, fmt.Sprintf("scanRequests=%t", *args.ScanRequests))
			}
			if args.PersistFindings != nil {
				cfg.PersistFindings = *args.PersistFindings
				changed = append(changed, fmt.Sprintf("persistFindings=%t", *args.PersistFindings))
			}
			if args.ClearFindingsWithHistory != nil {
				cfg.ClearFindingsWithHistory = *args.ClearFindingsWithHistory
				changed = append(changed, fmt.Sprintf("clearFindingsWithHistory=%t", *args.ClearFindingsWithHistory))
			}
			if args.MaxBodyScanBytes != nil {
				cfg.MaxBodyScanBytes = *args.MaxBodyScanBytes
				changed = append(changed, fmt.Sprintf("maxBodyScanBytes=%d", *args.MaxBodyScanBytes))
			}
			if args.MaxRequestBodyScanBytes != nil {
				cfg.MaxRequestBodyScanBytes = *args.MaxRequestBodyScanBytes
				changed = append(changed, fmt.Sprintf("maxRequestBodyScanBytes=%d", *args.MaxRequestBodyScanBytes))
			}
			if args.ExcludeHosts != nil {
				cfg.ExcludeHosts = slices.Clone(*args.ExcludeHosts)
				changed = append(changed, fmt.Sprintf("excludeHosts=%d entries", len(cfg.ExcludeHosts)))
			}
			if len(changed) == 0 {
				return nil, fmt.Errorf("nothing to do: supply at least one field to change")
			}
			d.Engine.SetConfig(cfg)
			capability.RecordChange(ctx, "detect config %s", strings.Join(changed, " "))
			return "updated: " + strings.Join(changed, " "), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "detect.rescan",
		Class:    capability.ClassDetect,
		Title:    "Rescan captured traffic",
		Mutating: true,
		Description: "Re-run detection over traffic already captured, which is how a rule you just added or " +
			"enabled reaches requests from before the change. Returns as soon as the job starts, so poll " +
			"findings_list rather than waiting. Findings are deduplicated by identity, so a rescan never " +
			"duplicates one, and existing triage — false-positive marks, notes, severity overrides — is " +
			"preserved. Nothing is deleted. Only one scan runs at a time.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "scope": {"type":"string","enum":["all","host"],"description":"Rescan everything, or one host. Default all."},
    "host":  {"type":"string","description":"Required when scope is \"host\"."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"scope":"all"}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args detectRescanArgs) (any, error) {
			if d.Scanner == nil {
				return nil, fmt.Errorf("the detection scanner is unavailable")
			}
			scope := orDefault(args.Scope, "all")
			if scope != "all" && scope != "host" {
				return nil, fmt.Errorf(`scope must be "all" or "host"`)
			}
			if scope == "host" && strings.TrimSpace(args.Host) == "" {
				return nil, fmt.Errorf(`host is required when scope is "host"`)
			}

			// Purge is deliberately not exposed: it deletes findings, and a rescan is
			// otherwise a purely additive operation an agent can run freely.
			req := detect.RescanRequest{Scope: scope, Host: strings.TrimSpace(args.Host), Purge: false}

			// The server-lifetime context, not this handler's: a rescan of a full
			// capture store outlasts the 30s invocation timeout, and cancelling it
			// partway would leave the operator with findings from a half-scan.
			bg := context.Background()
			if d.BgCtx != nil {
				if c := d.BgCtx(); c != nil {
					bg = c
				}
			}
			status, err := d.Scanner.StartRescan(bg, req)
			if err != nil {
				if errors.Is(err, detect.ErrScanRunning) {
					cur := d.Scanner.Status()
					return nil, fmt.Errorf("a scan is already running (%s, %d/%d scanned); "+
						"wait for it to finish", cur.Kind, cur.Scanned, cur.Total)
				}
				return nil, err
			}
			capability.RecordChange(ctx, "rescan scope=%s host=%s", scope, orDefault(req.Host, "*"))
			// Only point at findings_list if this token actually holds it; a token that
			// may tune detection but not read findings would otherwise spend a call
			// discovering the tool does not exist for it.
			next := "poll findings_list for results"
			if !p.Can("findings.list") {
				next = "results are visible to the operator in Joro's Detect tab, not from here"
			}
			return fmt.Sprintf("rescan started jobId=%s kind=%s total=%d; %s",
				status.JobID, status.Kind, status.Total, next), nil
		}),
	})
}

// detectRuleAdd builds a regex rule from the curated argument set. Analyzer rules are
// not creatable: their behavior is a Go function looked up by ID, so an operator-defined
// one has nothing to run.
func detectRuleAdd(ctx context.Context, d Deps, args detectRulesEditArgs) (any, error) {
	if n := len(d.Engine.UserRules()); n >= maxAgentDetectRules {
		return nil, fmt.Errorf("there are already %d operator-defined rules, at the %d limit; "+
			"every enabled rule runs against every scanned message", n, maxAgentDetectRules)
	}
	if strings.TrimSpace(args.Description) == "" {
		// The field is omitempty with no server-side check, and the UI renders it
		// conditionally with no fallback, so an empty one ships a rule whose name has
		// no subtitle anywhere.
		return nil, fmt.Errorf("description is required: it is what the operator reads under the rule name")
	}
	rule := detect.Rule{
		Name:           strings.TrimSpace(args.Name),
		Description:    strings.TrimSpace(args.Description),
		Kind:           detect.KindRegex,
		Category:       detect.Category(args.Category),
		Severity:       detect.Severity(args.Severity),
		Confidence:     detect.Confidence(orDefault(args.Confidence, string(detect.ConfidenceMedium))),
		Target:         detect.Target(orDefault(args.Target, string(detect.TargetResponseBody))),
		Pattern:        args.Pattern,
		Literal:        args.Literal,
		CaptureGroup:   args.CaptureGroup,
		MinLength:      args.MinLength,
		MinEntropy:     args.MinEntropy,
		ContentTypes:   slices.Clone(args.ContentTypes),
		GroupBy:        detect.GroupBy(args.GroupBy),
		RedactEvidence: args.RedactEvidence,
		Enabled:        true,
	}
	created, err := d.Engine.AddRule(rule)
	if err != nil {
		// Engine.AddRule runs ValidateRule, which surfaces the RE2 error text.
		return nil, err
	}
	capability.RecordChange(ctx, "add detect rule %s %q severity=%s pattern=%q",
		created.ID, created.Name, created.Severity, trunc(created.Pattern, 80))
	broadcastDetectRules(d)
	return fmt.Sprintf("added rule id=%s name=%q severity=%s category=%s target=%s\n"+
		"note: this applies to newly captured traffic only — call detect_rescan to apply it to existing history",
		created.ID, created.Name, created.Severity, created.Category, created.Target), nil
}

// describeRuleErr turns the engine's sentinel errors into something an agent can act
// on, rather than a bare "builtin rule is immutable".
func describeRuleErr(err error, id string) error {
	switch {
	case errors.Is(err, detect.ErrBuiltinImmutable):
		return fmt.Errorf("%s is a built-in rule, which cannot be added to or removed. "+
			"Use op setenabled to turn it off, or op setseverity to re-grade it", id)
	case errors.Is(err, detect.ErrRuleNotFound):
		return fmt.Errorf("no detection rule with id %s; list them with detect_rules_list", id)
	}
	return err
}

// broadcastDetectRules pushes the same event the REST rule handlers do, so the
// operator's Detect tab reflects an agent's change while it happens.
func broadcastDetectRules(d Deps) {
	if d.Engine == nil {
		return
	}
	broadcast(d, "detect.rules.changed", map[string]any{
		"builtinCount": len(d.Engine.Rules()) - len(d.Engine.UserRules()),
		"userCount":    len(d.Engine.UserRules()),
		"activeCount":  d.Engine.ActiveRuleCount(),
	})
}
