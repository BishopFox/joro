package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleGetInterceptQueue(w http.ResponseWriter, r *http.Request) {
	pending := s.intercept.List()

	type item struct {
		ID     string `json:"id"`
		Method string `json:"method"`
		URL    string `json:"url"`
		Host   string `json:"host"`
		ReqRaw string `json:"reqRaw"` // base64
	}

	items := make([]item, 0, len(pending))
	for _, p := range pending {
		items = append(items, item{
			ID:     p.ID,
			Method: p.Method,
			URL:    p.URL,
			Host:   p.Host,
			ReqRaw: base64.StdEncoding.EncodeToString(p.ReqRaw),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.intercept.IsEnabled(),
		"items":   items,
	})
}

func (s *APIServer) handleToggleIntercept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.intercept.SetEnabled(body.Enabled)

	s.mu.Lock()
	s.settings.InterceptEnabled = body.Enabled
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

func (s *APIServer) handleForwardRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		ReqRaw string `json:"reqRaw"` // base64-encoded modified raw request; optional
	}
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck

	var modifiedReq []byte
	if body.ReqRaw != "" {
		var err error
		modifiedReq, err = base64.StdEncoding.DecodeString(body.ReqRaw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid reqRaw base64")
			return
		}
	}

	ok := s.intercept.Resolve(id, proxy.InterceptDecision{
		Action:  proxy.ActionForward,
		ReqData: modifiedReq,
	})
	if !ok {
		writeError(w, http.StatusNotFound, "request not found in queue")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "forwarded"})
}

func (s *APIServer) handleDropRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	ok := s.intercept.Resolve(id, proxy.InterceptDecision{Action: proxy.ActionDrop})
	if !ok {
		writeError(w, http.StatusNotFound, "request not found in queue")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "dropped"})
}
