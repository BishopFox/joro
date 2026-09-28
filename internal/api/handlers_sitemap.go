package api

import (
	"net/http"
	"net/url"

	"github.com/BishopFox/joro/internal/echo"
)

// maxInventoryRequests bounds the walk behind a parameter inventory. History
// holds thousands of requests and a hot endpoint can hold most of them, so the
// newest slice is walked and the response says so rather than the pane stalling.
const maxInventoryRequests = 1000

func (s *APIServer) handleGetSitemap(w http.ResponseWriter, r *http.Request) {
	f := s.requestFilterFromQuery(r)
	hosts := s.store.Sitemap(f)
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

// handleGetSitemapParams inventories the parameters behind a site-map node: every
// input its requests carried, across every source, with counts. It takes the same
// request filters as handleGetSitemap, so the pane describes the node the operator
// clicked in the tree they are looking at.
//
// The node is named by "origin", not by "host" as handleDeleteSitemap names it.
// This endpoint also parses the shared request filters, where "host" already means
// a case-insensitive substring of the captured Host header — and an origin carries
// a scheme, so it is never a substring of one. Reusing the name here would filter
// every request away and report an endpoint with no parameters rather than fail.
//
// The walk is on demand and depends on nothing the reflection engine does: it
// answers for an operator who has never switched Echo on, which is the default.
func (s *APIServer) handleGetSitemapParams(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	origin := q.Get("origin")
	if origin == "" {
		writeError(w, http.StatusBadRequest, "origin is required")
		return
	}
	matchPath := q.Has("path")
	path := q.Get("path")

	reqs := s.store.NodeRequests(origin, path, matchPath, s.requestFilterFromQuery(r))
	total := len(reqs)
	walked := reqs
	if len(walked) > maxInventoryRequests {
		walked = walked[:maxInventoryRequests]
	}

	// The engine's configuration when it is wired, so the operator's body-scan
	// bounds apply; defaults otherwise, because the inventory has to work wherever
	// the site map does.
	cfg := echo.DefaultConfig()
	if s.echoEngine != nil {
		cfg = s.echoEngine.Config()
	}

	rows := echo.Inventory(walked, cfg)
	s.markReflected(origin, rows)

	writeJSON(w, http.StatusOK, map[string]any{
		"origin":    origin,
		"path":      path,
		"requests":  total,
		"walked":    len(walked),
		"truncated": len(walked) < total,
		"params":    rows,
	})
}

// markReflected flags the rows reflection mapping has already seen come back.
//
// The join key is the bare host. A site-map origin is scheme://host[:port] while
// echo keys an entry on detect.Message.Host, which is url.URL.Host — no scheme.
// Passing the origin through would hash a string no entry ever uses and leave
// every row silently unreflected.
func (s *APIServer) markReflected(origin string, rows []echo.ParamRow) {
	if s.echoStore == nil {
		return
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return
	}
	for i := range rows {
		e, ok := s.echoStore.Entry(echo.EntryID(u.Host, rows[i].Source, rows[i].Name))
		if !ok {
			continue
		}
		rows[i].Reflected = true
		rows[i].Breakouts = e.Breakouts
	}
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
