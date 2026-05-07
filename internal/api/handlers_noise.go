package api

import (
	"encoding/json"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleGetNoise(w http.ResponseWriter, r *http.Request) {
	patterns := s.noise.Patterns()
	if patterns == nil {
		patterns = []proxy.NoisePattern{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  s.noise.IsEnabled(),
		"patterns": patterns,
	})
}

func (s *APIServer) handleSetNoiseEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.noise.SetEnabled(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

func (s *APIServer) handleAddNoisePattern(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pattern string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required")
		return
	}
	p := s.noise.AddPattern(body.Pattern)
	writeJSON(w, http.StatusCreated, p)
}

func (s *APIServer) handleDeleteNoisePattern(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.noise.RemovePattern(id) {
		writeError(w, http.StatusNotFound, "pattern not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
