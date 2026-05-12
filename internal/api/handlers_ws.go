package api

import (
	"net/http"
	"strconv"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleListWSMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}

	items, total := s.wsStore.List(proxy.WSMessageFilter{
		Host:   q.Get("host"),
		Offset: offset,
		Limit:  limit,
	})
	if items == nil {
		items = []*proxy.CapturedWSMessage{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleClearWSMessages(w http.ResponseWriter, r *http.Request) {
	s.wsStore.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}
