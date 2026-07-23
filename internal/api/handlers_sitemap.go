package api

import "net/http"

func (s *APIServer) handleGetSitemap(w http.ResponseWriter, r *http.Request) {
	f := s.requestFilterFromQuery(r)
	hosts := s.store.Sitemap(f)
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

// handleDeleteSitemap removes the captured requests behind a site-map node. A
// "host" query param (origin, scheme://host[:port]) is required. An optional
// "path" param scopes the deletion to a single endpoint; when it is present the
// deletion matches that exact path (host-level otherwise). This removes the
// underlying requests, so they also disappear from history.
func (s *APIServer) handleDeleteSitemap(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	origin := q.Get("host")
	if origin == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	matchPath := q.Has("path")
	removed := s.store.DeleteSitemapNode(origin, q.Get("path"), matchPath)
	writeJSON(w, http.StatusOK, map[string]int{"deleted": removed})
}
