package proxy

import (
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
