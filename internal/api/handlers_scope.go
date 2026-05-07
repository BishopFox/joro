package api

import (
	"encoding/json"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
)

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
	if body.Pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required")
		return
	}
	rule := s.scope.AddRule(body)
	writeJSON(w, http.StatusCreated, rule)
}

func (s *APIServer) handleDeleteScopeRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.scope.RemoveRule(id) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
