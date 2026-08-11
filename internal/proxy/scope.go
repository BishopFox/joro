package proxy

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// ScopeRule defines a single include or exclude scope rule.
type ScopeRule struct {
	ID      string   `json:"id"`
	Pattern string   `json:"pattern"` // host glob: "*.target.com"
	Methods []string `json:"methods"` // e.g. ["POST","PUT"], empty = all
	Path    string   `json:"path"`    // path glob: "/api/*", empty = all
	Include bool     `json:"include"` // true=include, false=exclude
}

// Field bounds for a scope rule. A host glob has no reason to exceed the 253-byte
// DNS name limit by much, and a path glob is bounded by a realistic request target.
const (
	MaxScopePatternLen = 256
	MaxScopePathLen    = 1024
	MaxScopeMethods    = 16
)

// ValidateScopeRule normalizes a rule in place and reports whether it is usable.
//
// matchRule treats filepath.Match's ErrBadPattern as "no match", so without this a
// malformed glob is accepted and then silently matches nothing. The same is true of
// a host pattern carrying a scheme or path: '/' never appears in a hostname, and
// Match's '*' does not cross '/', so such a pattern can never match either.
func ValidateScopeRule(r *ScopeRule) error {
	// matchRule lowercases the host pattern before matching, so store it lowercased:
	// that makes two case-differing patterns compare equal for dedupe instead of both
	// being kept. The path is matched case-sensitively and is left alone.
	r.Pattern = strings.ToLower(strings.TrimSpace(r.Pattern))
	r.Path = strings.TrimSpace(r.Path)

	if r.Pattern == "" {
		return fmt.Errorf("pattern is required")
	}
	if len(r.Pattern) > MaxScopePatternLen {
		return fmt.Errorf("host pattern exceeds %d bytes", MaxScopePatternLen)
	}
	if strings.Contains(r.Pattern, "/") {
		return fmt.Errorf("host pattern must be a hostname without a scheme or path; put the path in the path field")
	}
	if err := validateGlob(r.Pattern); err != nil {
		return fmt.Errorf("invalid host pattern: %w", err)
	}

	if len(r.Path) > MaxScopePathLen {
		return fmt.Errorf("path pattern exceeds %d bytes", MaxScopePathLen)
	}
	if r.Path != "" {
		if err := validateGlob(r.Path); err != nil {
			return fmt.Errorf("invalid path pattern: %w", err)
		}
	}

	// Uppercase and drop blanks so rules from the UI form and from an import
	// compare equal. matchRule itself is case-insensitive.
	methods := make([]string, 0, len(r.Methods))
	for _, m := range r.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if !isMethodToken(m) {
			return fmt.Errorf("invalid method %q", m)
		}
		methods = append(methods, m)
	}
	if len(methods) > MaxScopeMethods {
		return fmt.Errorf("at most %d methods per rule", MaxScopeMethods)
	}
	r.Methods = methods

	return nil
}

// validateGlob reports whether a pattern is syntactically valid. Match validates the
// remainder of a pattern even once the match has failed, so any sample name works.
func validateGlob(pattern string) error {
	_, err := filepath.Match(pattern, "")
	return err
}

// isMethodToken reports whether s looks like an HTTP method name.
func isMethodToken(s string) bool {
	if len(s) == 0 || len(s) > 20 {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && c != '-' {
			return false
		}
	}
	return true
}

// Scope manages host and request-level scope filtering.
type Scope struct {
	mu      sync.RWMutex
	enabled bool
	rules   []ScopeRule
}

// NewScope creates a Scope that is disabled by default with no rules.
func NewScope() *Scope {
	return &Scope{}
}

// IsEnabled reports whether scope filtering is active.
func (s *Scope) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// SetEnabled enables or disables scope filtering.
func (s *Scope) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
}

// Rules returns a copy of the current scope rules.
func (s *Scope) Rules() []ScopeRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScopeRule, len(s.rules))
	copy(out, s.rules)
	return out
}

// RuleCount returns the number of configured scope rules.
//
// Scope with zero rules blocks everything, and InScope reports true when scope is
// disabled entirely — so a caller deciding whether scope is a usable authorization
// signal needs the count as well as the enabled flag. The automation guard uses
// both to fail closed. See internal/capability/guard.go.
func (s *Scope) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

// SetRules replaces all scope rules.
func (s *Scope) SetRules(rules []ScopeRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = rules
}

// AddRule appends a rule, assigning it a generated ID.
func (s *Scope) AddRule(rule ScopeRule) ScopeRule {
	rule.ID = GenerateID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rule)
	return rule
}

// RemoveRule deletes a rule by ID. Returns true if found.
func (s *Scope) RemoveRule(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rules {
		if r.ID == id {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			return true
		}
	}
	return false
}

// HostInScope checks if a hostname passes scope at the CONNECT level (host only).
func (s *Scope) HostInScope(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inScope(host, "", "")
}

// InScope checks if a request passes scope (host + method + path).
func (s *Scope) InScope(host, method, path string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inScope(host, method, path)
}

// inScope implements the evaluation logic. Must be called with mu held.
func (s *Scope) inScope(host, method, path string) bool {
	if !s.enabled {
		return true
	}
	if len(s.rules) == 0 {
		return false
	}

	included := false
	for _, r := range s.rules {
		if !r.Include {
			continue
		}
		if matchRule(r, host, method, path) {
			included = true
			break
		}
	}
	if !included {
		return false
	}

	for _, r := range s.rules {
		if r.Include {
			continue
		}
		if matchRule(r, host, method, path) {
			return false
		}
	}
	return true
}

// matchRule checks whether a single rule matches the given host, method, and path.
// When method or path is empty (Level 1 check), those dimensions are skipped.
func matchRule(rule ScopeRule, host, method, path string) bool {
	if rule.Pattern != "" {
		matched, err := filepath.Match(strings.ToLower(rule.Pattern), strings.ToLower(host))
		if err != nil || !matched {
			return false
		}
	}

	if method != "" && len(rule.Methods) > 0 {
		found := false
		for _, m := range rule.Methods {
			if strings.EqualFold(m, method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if path != "" && rule.Path != "" {
		matched, err := filepath.Match(rule.Path, path)
		if err != nil || !matched {
			return false
		}
	}

	return true
}
