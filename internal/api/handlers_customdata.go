package api

import (
	"encoding/json"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleGetCustomData(w http.ResponseWriter, r *http.Request) {
	items := s.customData.Items()
	if items == nil {
		items = []proxy.CustomAddition{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.customData.IsEnabled(),
		"items":   items,
	})
}

func (s *APIServer) handleSetCustomDataEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.customData.SetEnabled(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

func (s *APIServer) handleAddCustomDataItem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	valid := map[string]bool{"header": true, "query": true, "body": true}
	if !valid[body.Type] {
		writeError(w, http.StatusBadRequest, "type must be header, query, or body")
		return
	}
	if body.Type != "body" && body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required for header and query items")
		return
	}
	if body.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}
	item := s.customData.AddItem(body.Type, body.Name, body.Value)
	writeJSON(w, http.StatusCreated, item)
}

func (s *APIServer) handleDeleteCustomDataItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.customData.RemoveItem(id) {
		writeError(w, http.StatusNotFound, "item not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
