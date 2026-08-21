package api

import (
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
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.setHighlight(id, body.Color)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// setHighlight colours one captured request, or clears it when color is empty. Shared
// with the history.highlight capability, which reaches it through capreg.Deps.
func (s *APIServer) setHighlight(id, color string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if color == "" {
		delete(s.highlights, id)
		return
	}
	s.highlights[id] = color
}

func (s *APIServer) handleClearHighlights(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.highlights = make(map[string]string)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
