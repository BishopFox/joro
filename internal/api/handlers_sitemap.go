package api

import "net/http"

func (s *APIServer) handleGetSitemap(w http.ResponseWriter, r *http.Request) {
	f := s.requestFilterFromQuery(r)
	hosts := s.store.Sitemap(f)
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}
