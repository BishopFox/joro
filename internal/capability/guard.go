package capability

import (
	"net"
	"path/filepath"
	"strings"
)

// ScopeChecker is the subset of *proxy.Scope the guard needs. Declaring it here
// rather than importing internal/proxy keeps this package free of Joro's data
// path, and lets the guard matrix test run against a ten-line fake.
type ScopeChecker interface {
	IsEnabled() bool
	RuleCount() int
	InScope(host, method, path string) bool
}

// checkTarget evaluates whether a principal may emit traffic to a target.
//
// The rule is:
//
//	allow iff ( !RequireScope
//	            OR (scope enabled AND scope has >=1 rule AND target in scope) )
//	          AND ( HostAllow empty OR host matches HostAllow )
//
// The first clause fails closed, which it has to: proxy.Scope.InScope returns
// true when scope is *disabled* and false when it is enabled with no rules, so it
// is a capture filter, not an authorization control. Calling it alone would let an
// agent reach any host whenever the operator had not configured scope — the exact
// state a fresh install is in.
//
// The second clause ANDs rather than ORs. A host whitelist that could stand in for
// a disabled scope would reintroduce that same hole through a different field, so
// an operator who wants "just this host, scope off" has to say so explicitly by
// clearing RequireScope, which every audit entry then records.
//
// A nil ScopeChecker means Joro has no scope to consult (it should not happen in
// proxy mode) and is treated as scope-disabled.
func checkTarget(p Principal, sc ScopeChecker, t Target) error {
	host := normalizeHost(t.Host)
	if host == "" {
		return errf(CodeInvalidArgs, "could not determine a target host for this request")
	}

	if p.RequireScope {
		switch {
		case sc == nil || !sc.IsEnabled():
			return errf(CodeScopeDisabled,
				"scope is disabled in Joro, and this token requires an in-scope target. "+
					"Enable scope and add an include rule for %s, or issue a token with requireScope disabled.", host)
		case sc.RuleCount() == 0:
			return errf(CodeScopeEmpty,
				"scope is enabled but has no rules, so nothing is in scope. Add an include rule for %s.", host)
		case !inScopeEitherForm(sc, t, host):
			return errf(CodeOutOfScope,
				"%s %s on %s is not in scope. Add an include rule, or narrow the request to an in-scope target.",
				orAny(t.Method), orAny(t.Path), host)
		}
	}

	if len(p.HostAllow) > 0 && !matchesAnyGlob(p.HostAllow, host) {
		return errf(CodeHostNotAllowed,
			"%s is not in this token's host whitelist (%s).", host, strings.Join(p.HostAllow, ", "))
	}
	return nil
}

// inScopeEitherForm tests the target against scope using both the port-stripped
// host and the original host:port.
//
// This is not belt-and-braces, it reconciles a real inconsistency in the proxy
// itself: the CONNECT and MITM paths check scope against a bare hostname
// (mitm.go), while the plain-HTTP path checks r.Host, which carries the port
// (handler.go). On 80 and 443 those agree, so the difference is invisible; on a
// non-default port an operator's rule matches one and not the other.
//
// Accepting either form means a rule the operator wrote in either style
// authorizes the send. Checking only the stripped form would refuse a send to a
// host the operator had explicitly scoped as "host:8443" — denying something they
// asked for, which is the worse of the two failure directions. It does not widen
// scope: both forms are still evaluated by Joro's own rule engine.
func inScopeEitherForm(sc ScopeChecker, t Target, host string) bool {
	if sc.InScope(host, t.Method, t.Path) {
		return true
	}
	raw := strings.ToLower(strings.TrimSpace(t.Host))
	return raw != host && sc.InScope(raw, t.Method, t.Path)
}

func orAny(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// matchesAnyGlob reports whether host matches any pattern, using the same
// filepath.Match semantics proxy.Scope uses for its host patterns, so an operator
// writing a whitelist entry gets the behavior they already know from scope rules.
//
// That inherits filepath.Match's surprise: * does not stop at a dot, so "*.com"
// matches "evil.attacker.com", and "*.target.com" does not match bare
// "target.com". The grant editor shows a live match preview rather than this
// package quietly using different rules than the scope engine.
func matchesAnyGlob(patterns []string, host string) bool {
	for _, pat := range patterns {
		p := strings.ToLower(strings.TrimSpace(pat))
		if p == "" {
			continue
		}
		if ok, err := filepath.Match(p, host); err == nil && ok {
			return true
		}
	}
	return false
}

// normalizeHost strips a port, lowercases, and drops a trailing root dot, so
// "API.Target.com.:443" and "api.target.com" compare equal. Mirrors the port
// handling in internal/api.reqHostname, which is unexported there.
func normalizeHost(hostport string) string {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}
