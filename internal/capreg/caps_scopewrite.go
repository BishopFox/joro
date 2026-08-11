package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/proxy"
)

// Scope writes, and the reasoning that makes them safe to expose at all.
//
// capability.Register panics on a mutating scope-class capability unless it sets
// UnrestrictedOnly, which confines it to a token with RequireScope off and no host
// whitelist. For such a token checkTarget already admits every host — the scope
// clause is skipped and the whitelist clause is vacuous — so editing scope grants it
// no reach it did not have. A token leashed *by* scope still cannot touch scope,
// which is the property the original blanket panic protected.
//
// The verb set is deliberately narrow: add an include rule, and enable scope. There
// is no exclude verb, no remove verb and no disable verb, because those are the only
// scope operations that reduce what Joro observes, and reducing observation is an
// evidence-suppression primitive on exactly the RequireScope-off token this permits.
// An agent could otherwise exclude its own targets, keep sending successfully — the
// send path reads responses itself, and history correlation is optional — and leave
// the operator with no captured record of the agent's traffic. Add-only means a scope
// write can only ever cause more traffic to be recorded, never less.
//
// What an operator is accepting by granting these: scope is the interception
// decision, not merely a display filter, so adding an include rule makes Joro start
// terminating TLS for that host and recording its plaintext. The read capabilities
// are not bounded by a host whitelist, so an agent can add a rule, wait for the
// operator to browse there, and read the result. That is a real increment, and it is
// why the grant picker states it in as many words.
const maxAgentScopeRules = 1000

type scopeAddRuleArgs struct {
	Pattern string   `json:"pattern"`
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

func registerScopeWrite(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:               "scope.addrule",
		Class:            capability.ClassScope,
		Title:            "Add a scope include rule",
		Mutating:         true,
		UnrestrictedOnly: true,
		Description: "Add an include rule to Joro's scope, so traffic to a host is intercepted, captured and " +
			"scanned. Use this to set up an engagement before testing. Rules are include-only: there is no way " +
			"to add an exclude rule, remove a rule, or disable scope from here, because those reduce what Joro " +
			"records — ask the operator. Note that scope is the TLS-interception decision, so adding a rule " +
			"changes what Joro does to the operator's own browsing, and the change is written to their project " +
			"file. Available only to a token with requireScope disabled and no host whitelist.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "pattern": {"type":"string","description":"Host glob, e.g. \"api.target.com\" or \"*.target.com\". Note that * spans dots, so \"*.target.com\" matches \"a.b.target.com\" but not bare \"target.com\". Must not contain a slash."},
    "methods": {"type":"array","items":{"type":"string"},"description":"Methods this rule covers. Omit for all methods."},
    "path":    {"type":"string","description":"Path glob, e.g. \"/api/*\". Omit for all paths."}
  },
  "required":["pattern"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"pattern":"*.target.com"}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args scopeAddRuleArgs) (any, error) {
			if d.Scope == nil {
				return nil, fmt.Errorf("scope is unavailable")
			}
			if n := d.Scope.RuleCount(); n >= maxAgentScopeRules {
				return nil, fmt.Errorf("scope already holds %d rules, at the %d limit; "+
					"Scope.InScope is a linear scan on every proxied request, so this is a cap on the "+
					"operator's proxy performance rather than on you", n, maxAgentScopeRules)
			}

			// A handler-owned copy, with Methods cloned: Scope.AddRule stores what it
			// is given, and ScopeRule.Methods handed straight from a decoded argument
			// would otherwise be reachable from here after it went live.
			rule := proxy.ScopeRule{
				Pattern: args.Pattern,
				Methods: slices.Clone(args.Methods),
				Path:    args.Path,
				Include: true, // exclude is unrepresentable, see the file comment
			}
			if err := proxy.ValidateScopeRule(&rule); err != nil {
				return nil, err
			}
			created := d.Scope.AddRule(rule)

			// No WS event: there is no scope.changed event type, and the operator's
			// own scope REST handlers do not broadcast either, so the Scope panel
			// updates on reload. Activity is where this shows up live.
			capability.RecordChange(ctx, "add include host=%s methods=%s path=%s",
				created.Pattern, joinOr(created.Methods, "*"), orDefault(created.Path, "*"))

			out := fmt.Sprintf("added include rule id=%s host=%s methods=%s path=%s\nscope: enabled=%t rules=%d",
				created.ID, created.Pattern, joinOr(created.Methods, "*"), orDefault(created.Path, "*"),
				d.Scope.IsEnabled(), d.Scope.RuleCount())
			if !d.Scope.IsEnabled() {
				out += "\nnote: scope is disabled, so this rule has no effect yet — call scope_enable"
			}
			return out, nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:               "scope.enable",
		Class:            capability.ClassScope,
		Title:            "Enable scope filtering",
		Mutating:         true,
		UnrestrictedOnly: true,
		Description: "Turn on Joro's scope filtering, so only hosts matching an include rule are intercepted " +
			"and captured. Refused unless at least one include rule already exists: enabling scope with no " +
			"rules puts nothing in scope, which would silently stop Joro capturing anything at all. There is " +
			"no matching disable — ask the operator. Available only to a token with requireScope disabled and " +
			"no host whitelist.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Scope == nil {
				return nil, fmt.Errorf("scope is unavailable")
			}
			if d.Scope.IsEnabled() {
				return fmt.Sprintf("scope is already enabled (rules=%d)", d.Scope.RuleCount()), nil
			}

			// Enabled scope with no include rule matches nothing, and inScope then
			// returns false for every request: no capture, no detection, no intercept.
			// With no disable verb the agent could not undo it, so refuse instead.
			rules := d.Scope.Rules()
			if !slices.ContainsFunc(rules, func(rule proxy.ScopeRule) bool { return rule.Include }) {
				return nil, fmt.Errorf("refusing to enable scope with no include rule: %d rules present, "+
					"none of them an include. Enabled scope matches only what an include rule covers, so this "+
					"would stop Joro capturing anything. Add an include rule with scope_addrule first",
					len(rules))
			}
			d.Scope.SetEnabled(true)

			capability.RecordChange(ctx, "enable scope (rules=%d)", len(rules))
			return fmt.Sprintf("scope enabled with %d rules", len(rules)), nil
		}),
	})
}
