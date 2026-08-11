package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
)

// Bounds for a scope import. The body cap leaves room for well over the rule cap;
// both are here so a malformed or oversized file is rejected before it is decoded.
const (
	maxScopeImportBytes = 1 << 20
	maxScopeImportRules = 1000
)

// scopeImportRule mirrors projectScopeRule but makes include explicit. A plain bool
// cannot distinguish an omitted field from false, and false is "exclude" — so an
// omitted include would quietly invert the rule.
type scopeImportRule struct {
	Pattern string   `json:"pattern"`
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
	Include *bool    `json:"include"`
}

func (s *APIServer) handleGetScope(w http.ResponseWriter, r *http.Request) {
	rules := s.scope.Rules()
	if rules == nil {
		rules = []proxy.ScopeRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.scope.IsEnabled(),
		"rules":   rules,
	})
}

func (s *APIServer) handleSetScopeEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.scope.SetEnabled(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

func (s *APIServer) handleAddScopeRule(w http.ResponseWriter, r *http.Request) {
	var body proxy.ScopeRule
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := proxy.ValidateScopeRule(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule := s.scope.AddRule(body)
	writeJSON(w, http.StatusCreated, rule)
}

// handleImportScopeRules replaces or merges the scope rule set from an uploaded
// scope file. Every rule is validated before anything is applied: a file with one
// bad rule is rejected whole rather than landing half-applied.
func (s *APIServer) handleImportScopeRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config struct {
			ScopeEnabled *bool             `json:"scopeEnabled"`
			ScopeRules   []scopeImportRule `json:"scopeRules"`
		} `json:"config"`
		Mode string `json:"mode"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxScopeImportBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Require the mode outright rather than treating anything that isn't "merge"
	// as the destructive option.
	var merge bool
	switch body.Mode {
	case "merge":
		merge = true
	case "replace":
	default:
		writeError(w, http.StatusBadRequest, `mode must be "replace" or "merge"`)
		return
	}

	incoming := body.Config.ScopeRules
	if len(incoming) == 0 {
		writeError(w, http.StatusBadRequest, "no rules to import")
		return
	}
	if len(incoming) > maxScopeImportRules {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d rules per import", maxScopeImportRules))
		return
	}

	next := make([]proxy.ScopeRule, 0, len(incoming))
	if merge {
		next = append(next, s.scope.Rules()...)
	}
	imported := 0
	for i, in := range incoming {
		if in.Include == nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("rule %d: include is required", i))
			return
		}
		rule := proxy.ScopeRule{
			ID:      proxy.GenerateID(),
			Pattern: in.Pattern,
			Methods: in.Methods,
			Path:    in.Path,
			Include: *in.Include,
		}
		if err := proxy.ValidateScopeRule(&rule); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("rule %d: %v", i, err))
			return
		}
		// Compared against the growing set, so duplicates within the file collapse in
		// both modes; on merge that set also holds the existing rules.
		if containsScopeRule(next, projectScopeRule{
			Pattern: rule.Pattern, Methods: rule.Methods, Path: rule.Path, Include: rule.Include,
		}) {
			continue
		}
		next = append(next, rule)
		imported++
	}

	wasEnabled := s.scope.IsEnabled()
	s.scope.SetRules(next)
	if body.Config.ScopeEnabled != nil {
		s.scope.SetEnabled(*body.Config.ScopeEnabled || (merge && wasEnabled))
	}

	rules := s.scope.Rules()
	if rules == nil {
		rules = []proxy.ScopeRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  s.scope.IsEnabled(),
		"rules":    rules,
		"imported": imported,
		"skipped":  len(incoming) - imported,
	})
}

func (s *APIServer) handleDeleteScopeRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.scope.RemoveRule(id) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
