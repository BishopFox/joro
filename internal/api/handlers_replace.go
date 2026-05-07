package api

import (
	"encoding/json"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleGetReplace(w http.ResponseWriter, r *http.Request) {
	rules := s.replace.Rules()
	if rules == nil {
		rules = []proxy.MatchReplaceRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.replace.IsEnabled(),
		"rules":   rules,
	})
}

func (s *APIServer) handleSetReplaceEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.replace.SetEnabled(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

func (s *APIServer) handleAddReplaceRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target    string `json:"target"`
		MatchType string `json:"matchType"`
		Match     string `json:"match"`
		Replace   string `json:"replace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Target == "" || body.Match == "" {
		writeError(w, http.StatusBadRequest, "target and match are required")
		return
	}
	valid := map[string]bool{
		"request_header": true, "request_body": true,
		"response_header": true, "response_body": true,
		"ws_message": true,
	}
	if !valid[body.Target] {
		writeError(w, http.StatusBadRequest, "invalid target")
		return
	}
	if body.MatchType == "" {
		body.MatchType = "string"
	}
	rule := s.replace.AddRule(body.Target, body.MatchType, body.Match, body.Replace)
	writeJSON(w, http.StatusCreated, rule)
}

func (s *APIServer) handleDeleteReplaceRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.replace.RemoveRule(id) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
