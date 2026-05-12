package api

import (
	"encoding/json"
	"net/http"
)

func (s *APIServer) handleGetHighlights(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	h := make(map[string]string, len(s.highlights))
	for k, v := range s.highlights {
		h[k] = v
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"highlights": h})
}

func (s *APIServer) handleSetHighlight(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Color string `json:"color"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.mu.Lock()
	if body.Color == "" {
		delete(s.highlights, id)
	} else {
		s.highlights[id] = body.Color
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *APIServer) handleClearHighlights(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.highlights = make(map[string]string)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
