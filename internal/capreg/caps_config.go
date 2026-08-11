package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
)

// The config class: the proxy's behavioral rule stores.
//
// This is what "modify the proxy configuration" means for automation. Settings — the
// bind address, ports, SOCKS, the listener URL and the team token — lives on
// *api.APIServer and is unreachable from here, which is both the structural rule in
// build.go and the right answer: those are the knobs where a mistake stops being a
// configuration change and starts being an egress or exfiltration decision.
//
// Three constraints shape every handler below:
//
//  1. Use the stores' single-item methods (AddRule, AddItem, AddPattern, Remove*),
//     never Rules()+SetRules(). Those setters retain the caller's backing array, and
//     the accessors copy only the slice header, so a read-modify-write both aliases
//     live state and races the operator's own REST calls — an operator deleting a rule
//     while an agent adds one would see their delete resurrected.
//  2. Cap the store. None of these enforces a size limit of its own, and
//     MatchReplace.Apply runs on the proxy hot path for every request, so an unbounded
//     agent is a performance regression in the operator's browser.
//  3. Pre-validate, because two of the three stores swallow their errors.
//     MatchReplace.AddRule ignores the regexp.Compile error, so an invalid pattern
//     becomes a silently inert rule — the worst failure for an agent, which reads
//     success and concludes the rule fired. NoiseFilter does no glob validation at all.
const (
	maxAgentReplaceRules = 200
	maxAgentCustomItems  = 200
	maxAgentNoisePattern = 300
)

// replaceTargets is the set MatchReplace understands. The store takes a bare string
// and never validates it, so an unknown target would be stored and never match.
var replaceTargets = []string{
	"request_header", "request_body", "response_header", "response_body", "ws_message",
}

var customDataTypes = []string{"header", "query", "body"}

type replaceEditArgs struct {
	Op        string `json:"op"`
	ID        string `json:"id"`
	Target    string `json:"target"`
	MatchType string `json:"matchType"`
	Match     string `json:"match"`
	Replace   string `json:"replace"`
}

type customDataEditArgs struct {
	Op    string `json:"op"`
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type noiseEditArgs struct {
	Op      string `json:"op"`
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
}

func registerConfig(r *capability.Registry, d Deps) {
	registerReplace(r, d)
	registerCustomData(r, d)
	registerNoise(r, d)

	r.MustRegister(capability.Capability{
		ID:    "config.intercept.get",
		Class: capability.ClassConfig,
		Title: "Read intercept status",
		Description: "Whether the operator has request or response interception enabled, and how many items are " +
			"parked in their queue. Worth checking when a send times out: an enabled request intercept pauses " +
			"your request in the operator's queue until they act on it, and the tool's own timeout fires first — " +
			"which is otherwise indistinguishable from a slow target. Read-only; only the operator can toggle " +
			"interception or release a paused request.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Intercept == nil {
				return nil, fmt.Errorf("intercept is unavailable")
			}
			reqOn := d.Intercept.IsEnabled()
			out := fmt.Sprintf("requests=%s responses=%s pendingResponses=%d queued=%d",
				onOff(reqOn), onOff(d.Intercept.IsResponseEnabled()),
				d.Intercept.PendingResponses(), len(d.Intercept.List()))
			if reqOn {
				out += "\nnote: request interception is on, so a send of yours may be paused awaiting the operator"
			}
			return out, nil
		}),
	})
}

func registerReplace(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "config.replace.list",
		Class: capability.ClassConfig,
		Title: "List Match & Replace rules",
		Description: "Joro's Match & Replace rules and whether the feature is enabled. These rewrite raw bytes " +
			"on the way through the proxy, so they explain any difference between what you asked to send and " +
			"what reached the target, or between a response and what you read back.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Replace == nil {
				return nil, fmt.Errorf("match & replace is unavailable")
			}
			rules := d.Replace.Rules()
			var b strings.Builder
			fmt.Fprintf(&b, "enabled=%t rules=%d\n", d.Replace.IsEnabled(), len(rules))
			if len(rules) == 0 {
				return strings.TrimRight(b.String(), "\n") + "\n(no rules)", nil
			}
			for _, rule := range rules {
				fmt.Fprintf(&b, "%s %-16s %-6s %s -> %s\n", rule.ID, rule.Target, rule.MatchType,
					trunc(rule.Match, 60), trunc(rule.Replace, 60))
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "config.replace.edit",
		Class:    capability.ClassConfig,
		Title:    "Add or remove a Match & Replace rule",
		Mutating: true,
		Description: "Add or remove one Match & Replace rule. These rewrite bytes for all in-scope traffic, " +
			"including the operator's own browsing, so prefer a per-request edit via http_resend when you only " +
			"need to change one request. A regex pattern is compiled before it is stored and an invalid one is " +
			"rejected rather than silently kept. Feature-level enable/disable is the operator's, not yours.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "op":        {"type":"string","enum":["add","remove"],"description":"Which operation to perform."},
    "id":        {"type":"string","description":"remove only: the rule ID from config_replace_list."},
    "target":    {"type":"string","enum":["request_header","request_body","response_header","response_body","ws_message"],"description":"add only: which part of the message to rewrite."},
    "matchType": {"type":"string","enum":["string","regex"],"description":"add only: literal substring or RE2 regular expression. Default string."},
    "match":     {"type":"string","description":"add only: the text or RE2 pattern to find."},
    "replace":   {"type":"string","description":"add only: the replacement. May be empty, which deletes the match."}
  },
  "required":["op"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"op":"add","target":"request_header","matchType":"string","match":"User-Agent: curl","replace":"User-Agent: Mozilla/5.0"}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args replaceEditArgs) (any, error) {
			if d.Replace == nil {
				return nil, fmt.Errorf("match & replace is unavailable")
			}
			switch args.Op {
			case "add":
				if n := len(d.Replace.Rules()); n >= maxAgentReplaceRules {
					return nil, fmt.Errorf("match & replace already holds %d rules, at the %d limit; "+
						"every rule runs against every proxied message", n, maxAgentReplaceRules)
				}
				if !slices.Contains(replaceTargets, args.Target) {
					return nil, fmt.Errorf("target must be one of %s", strings.Join(replaceTargets, ", "))
				}
				if args.Match == "" {
					return nil, fmt.Errorf("match is required and must not be empty")
				}
				matchType := orDefault(args.MatchType, "string")
				switch matchType {
				case "string":
				case "regex":
					// The store discards this error and keeps an inert rule, so this
					// check is the only thing standing between a bad pattern and an
					// agent that believes it installed one.
					if _, err := regexp.Compile(args.Match); err != nil {
						return nil, fmt.Errorf("match is not a valid RE2 pattern: %w", err)
					}
				default:
					return nil, fmt.Errorf(`matchType must be "string" or "regex"`)
				}
				rule := d.Replace.AddRule(args.Target, matchType, args.Match, args.Replace)
				capability.RecordChange(ctx, "add replace %s %s match=%q replace=%q",
					rule.Target, rule.MatchType, trunc(rule.Match, 80), trunc(rule.Replace, 80))
				return fmt.Sprintf("added rule id=%s target=%s type=%s (enabled=%t)",
					rule.ID, rule.Target, rule.MatchType, d.Replace.IsEnabled()), nil

			case "remove":
				if args.ID == "" {
					return nil, fmt.Errorf("id is required to remove a rule")
				}
				if !d.Replace.RemoveRule(args.ID) {
					return nil, fmt.Errorf("no match & replace rule with id %s", args.ID)
				}
				capability.RecordChange(ctx, "remove replace rule id=%s", args.ID)
				return fmt.Sprintf("removed rule id=%s", args.ID), nil
			}
			return nil, fmt.Errorf(`op must be "add" or "remove"`)
		}),
	})
}

func registerCustomData(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "config.customdata.list",
		Class: capability.ClassConfig,
		Title: "List Custom Data items",
		Description: "Joro's Custom Data items and whether the feature is enabled. These are appended to every " +
			"in-scope request — headers, query parameters or body data — after Match & Replace runs, so they " +
			"also explain a difference between what you sent and what arrived.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.CustomData == nil {
				return nil, fmt.Errorf("custom data is unavailable")
			}
			items := d.CustomData.Items()
			var b strings.Builder
			fmt.Fprintf(&b, "enabled=%t items=%d\n", d.CustomData.IsEnabled(), len(items))
			if len(items) == 0 {
				return strings.TrimRight(b.String(), "\n") + "\n(no items)", nil
			}
			for _, it := range items {
				fmt.Fprintf(&b, "%s %-6s %s = %s\n", it.ID, it.Type, it.Name, trunc(it.Value, 80))
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "config.customdata.edit",
		Class:    capability.ClassConfig,
		Title:    "Add or remove a Custom Data item",
		Mutating: true,
		Description: "Add or remove one Custom Data item. Unlike Match & Replace this is purely additive — it " +
			"needs no pattern — which makes it the right way to attach an auth header or a tracking parameter " +
			"to every in-scope request for the rest of the engagement. It applies to the operator's own " +
			"browsing too. Feature-level enable/disable is the operator's, not yours.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "op":    {"type":"string","enum":["add","remove"],"description":"Which operation to perform."},
    "id":    {"type":"string","description":"remove only: the item ID from config_customdata_list."},
    "type":  {"type":"string","enum":["header","query","body"],"description":"add only: what kind of data to append."},
    "name":  {"type":"string","description":"add only: header or parameter name. Ignored for type body."},
    "value": {"type":"string","description":"add only: the value, or the body fragment for type body."}
  },
  "required":["op"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"op":"add","type":"header","name":"X-Bug-Bounty","value":"researcher-handle"}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args customDataEditArgs) (any, error) {
			if d.CustomData == nil {
				return nil, fmt.Errorf("custom data is unavailable")
			}
			switch args.Op {
			case "add":
				if n := len(d.CustomData.Items()); n >= maxAgentCustomItems {
					return nil, fmt.Errorf("custom data already holds %d items, at the %d limit", n, maxAgentCustomItems)
				}
				if !slices.Contains(customDataTypes, args.Type) {
					return nil, fmt.Errorf("type must be one of %s", strings.Join(customDataTypes, ", "))
				}
				if args.Type != "body" && strings.TrimSpace(args.Name) == "" {
					return nil, fmt.Errorf("name is required for type %s", args.Type)
				}
				item := d.CustomData.AddItem(args.Type, args.Name, args.Value)
				capability.RecordChange(ctx, "add customdata %s %s=%q",
					item.Type, item.Name, trunc(item.Value, 80))
				return fmt.Sprintf("added item id=%s type=%s name=%s (enabled=%t)",
					item.ID, item.Type, item.Name, d.CustomData.IsEnabled()), nil

			case "remove":
				if args.ID == "" {
					return nil, fmt.Errorf("id is required to remove an item")
				}
				if !d.CustomData.RemoveItem(args.ID) {
					return nil, fmt.Errorf("no custom data item with id %s", args.ID)
				}
				capability.RecordChange(ctx, "remove customdata item id=%s", args.ID)
				return fmt.Sprintf("removed item id=%s", args.ID), nil
			}
			return nil, fmt.Errorf(`op must be "add" or "remove"`)
		}),
	})
}

func registerNoise(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "config.noise.list",
		Class: capability.ClassConfig,
		Title: "List noise filter patterns",
		Description: "The host patterns Joro tunnels silently without capturing — browser background traffic " +
			"such as telemetry, OCSP and captive-portal checks. Worth reading when a host you expect to see is " +
			"absent from history: a noise match is checked before scope and leaves no record at all.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Noise == nil {
				return nil, fmt.Errorf("noise filter is unavailable")
			}
			pats := d.Noise.Patterns()
			var b strings.Builder
			fmt.Fprintf(&b, "enabled=%t patterns=%d\n", d.Noise.IsEnabled(), len(pats))
			for _, p := range pats {
				fmt.Fprintf(&b, "%s %s\n", p.ID, p.Pattern)
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "config.noise.edit",
		Class:    capability.ClassConfig,
		Title:    "Add or remove a noise filter pattern",
		Mutating: true,
		Description: "Add or remove one noise pattern. Be careful adding: a noise match is checked before scope " +
			"and leaves no trace whatsoever — no history row, no detection, and nothing a rescan can recover — " +
			"so a pattern broad enough to cover a target silently discards its traffic. Patterns are host globs " +
			"where * spans dots, so \"*.example.com\" also matches \"a.b.example.com\".",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "op":      {"type":"string","enum":["add","remove"],"description":"Which operation to perform."},
    "id":      {"type":"string","description":"remove only: the pattern ID from config_noise_list."},
    "pattern": {"type":"string","description":"add only: a host glob, e.g. \"*.telemetry.example.com\"."}
  },
  "required":["op"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"op":"add","pattern":"*.telemetry.example.com"}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args noiseEditArgs) (any, error) {
			if d.Noise == nil {
				return nil, fmt.Errorf("noise filter is unavailable")
			}
			switch args.Op {
			case "add":
				if n := len(d.Noise.Patterns()); n >= maxAgentNoisePattern {
					return nil, fmt.Errorf("noise filter already holds %d patterns, at the %d limit", n, maxAgentNoisePattern)
				}
				pattern := strings.ToLower(strings.TrimSpace(args.Pattern))
				if pattern == "" {
					return nil, fmt.Errorf("pattern is required and must not be empty")
				}
				if strings.Contains(pattern, "/") {
					return nil, fmt.Errorf("pattern %q contains a slash: noise patterns match a hostname, "+
						"which never contains one, so this could never match", pattern)
				}
				// The store never validates the glob, and filepath.Match reports a bad
				// pattern as "no match", so an invalid one would sit there inert.
				if _, err := filepath.Match(pattern, "probe.example.com"); err != nil {
					return nil, fmt.Errorf("pattern %q is not a valid glob: %w", pattern, err)
				}
				added := d.Noise.AddPattern(pattern)
				capability.RecordChange(ctx, "add noise pattern %s", added.Pattern)
				return fmt.Sprintf("added pattern id=%s %s (enabled=%t)\n"+
					"note: traffic matching this is now tunneled with no record kept",
					added.ID, added.Pattern, d.Noise.IsEnabled()), nil

			case "remove":
				if args.ID == "" {
					return nil, fmt.Errorf("id is required to remove a pattern")
				}
				if !d.Noise.RemovePattern(args.ID) {
					return nil, fmt.Errorf("no noise pattern with id %s", args.ID)
				}
				capability.RecordChange(ctx, "remove noise pattern id=%s", args.ID)
				return fmt.Sprintf("removed pattern id=%s", args.ID), nil
			}
			return nil, fmt.Errorf(`op must be "add" or "remove"`)
		}),
	})
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
