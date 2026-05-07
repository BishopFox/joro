package api

import "net/http"

func (s *APIServer) handleGetSitemap(w http.ResponseWriter, r *http.Request) {
	hosts := s.store.Sitemap()
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}
