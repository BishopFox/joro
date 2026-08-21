package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleGetInterceptQueue(w http.ResponseWriter, r *http.Request) {
	pending := s.intercept.List()

	type item struct {
		ID       string    `json:"id"`
		Kind     string    `json:"kind"`
		Method   string    `json:"method"`
		URL      string    `json:"url"`
		Host     string    `json:"host"`
		Protocol string    `json:"protocol,omitempty"`
		Status   int       `json:"status,omitempty"`
		PausedAt time.Time `json:"pausedAt"`
		ReqRaw   string    `json:"reqRaw"`            // base64
		RespRaw  string    `json:"respRaw,omitempty"` // base64, response pauses only
	}

	items := make([]item, 0, len(pending))
	for _, p := range pending {
		it := item{
			ID:       p.ID,
			Kind:     string(p.Kind),
			Method:   p.Method,
			URL:      p.URL,
			Host:     p.Host,
			Protocol: p.Protocol,
			Status:   p.Status,
			PausedAt: p.PausedAt,
			ReqRaw:   base64.StdEncoding.EncodeToString(p.ReqRaw),
		}
		if len(p.RespRaw) > 0 {
			it.RespRaw = base64.StdEncoding.EncodeToString(p.RespRaw)
		}
		items = append(items, it)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":          s.intercept.IsEnabled(),
		"responsesEnabled": s.intercept.IsResponseEnabled(),
		"items":            items,
	})
}

func (s *APIServer) handleToggleIntercept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.intercept.SetEnabled(body.Enabled)

	s.mu.Lock()
	s.settings.InterceptEnabled = body.Enabled
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

// handleToggleInterceptResponses toggles response interception. This is a
// separate route from PUT /intercept/enabled rather than a second field on it: a
// shared body would let a client sending only one phase clobber the other to
// false via the zero value.
func (s *APIServer) handleToggleInterceptResponses(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.setInterceptResponses(body.Enabled)

	writeJSON(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

// setInterceptResponses updates the queue and the Settings mirror together, so
// the two cannot drift. The queue is set outside s.mu because disabling drains
// pending pauses.
func (s *APIServer) setInterceptResponses(enabled bool) {
	s.mu.Lock()
	s.settings.InterceptResponses = enabled
	s.mu.Unlock()

	if s.intercept != nil {
		s.intercept.SetResponseEnabled(enabled)
	}
}

// handleReleaseIntercepts forwards every pending pause unmodified. This is the
// recovery path when several paused responses have stalled an origin: browsers
// cap concurrent connections per host, so the alternative is resolving each by
// hand or waiting out the auto-forward timeout.
//
// Forward-only by design — a bulk drop is destructive with no undo.
func (s *APIServer) handleReleaseIntercepts(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind string `json:"kind"` // "request" | "response"; empty means both
	}
	// Optional: an absent body means both phases. A body that was sent and could not be
	// read is reported rather than ignored — silently treating it as absent would release
	// both phases when the caller asked for one.
	if err := decodeJSONOptional(r, &body, maxJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	switch proxy.InterceptKind(body.Kind) {
	case proxy.KindRequest, proxy.KindResponse, "":
	default:
		writeError(w, http.StatusBadRequest, "kind must be request, response, or omitted")
		return
	}

	released := s.intercept.DrainAll(proxy.InterceptKind(body.Kind))
	writeJSON(w, http.StatusOK, map[string]int{"released": released})
}

func (s *APIServer) handleForwardRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		ReqRaw  string `json:"reqRaw"`  // base64-encoded modified raw request; optional
		RespRaw string `json:"respRaw"` // base64-encoded modified raw response; optional
	}
	// Bulk, and the whole body is optional: forwarding unmodified sends no fields. A body
	// that was sent and could not be read is reported rather than ignored — silently
	// treating it as absent would forward the original request the operator had edited.
	if err := decodeJSONOptional(r, &body, maxBulkJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var modifiedReq, modifiedResp []byte
	if body.ReqRaw != "" {
		var err error
		modifiedReq, err = base64.StdEncoding.DecodeString(body.ReqRaw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid reqRaw base64")
			return
		}
	}
	if body.RespRaw != "" {
		var err error
		modifiedResp, err = base64.StdEncoding.DecodeString(body.RespRaw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid respRaw base64")
			return
		}
	}

	// Resolve is phase-agnostic: each pause site reads only the field it needs.
	ok := s.intercept.Resolve(id, proxy.InterceptDecision{
		Action:   proxy.ActionForward,
		ReqData:  modifiedReq,
		RespData: modifiedResp,
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
