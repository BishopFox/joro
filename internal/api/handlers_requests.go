package api

import (
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/BishopFox/joro/internal/echo"
	"github.com/BishopFox/joro/internal/proxy"
)

// requestFilterFromQuery builds a proxy.RequestFilter from the shared request
// query params (host/method/status/search/content/scope/...). Used by both the
// history listing and the site map so they filter identically. Offset/Limit are
// parsed here too; callers that don't paginate simply ignore them.
func (s *APIServer) requestFilterFromQuery(r *http.Request) proxy.RequestFilter {
	q := r.URL.Query()

	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))

	extMode := q.Get("extMode")
	if extMode == "" {
		extMode = "exclude"
	}

	f := proxy.RequestFilter{
		Host:         q.Get("host"),
		Method:       q.Get("method"),
		Status:       q.Get("status"),
		Search:       q.Get("search"),
		Exclude:      q.Get("exclude"),
		ExtMode:      extMode,
		ContentType:  q.Get("contentType"),
		Content:      q.Get("content"),
		ContentMode:  q.Get("contentMode"),
		ContentRegex: q.Get("contentRegex") == "true",
		Offset:       offset,
		Limit:        limit,
	}

	if q.Get("scope_only") == "true" && s.scope != nil {
		f.InScopeFunc = s.scope.InScope
	}

	return f
}

func (s *APIServer) handleListRequests(w http.ResponseWriter, r *http.Request) {
	f := s.requestFilterFromQuery(r)

	items, total := s.store.List(f)

	type summary struct {
		ID           string `json:"id"`
		Seq          int    `json:"seq"`
		Timestamp    string `json:"timestamp"`
		Method       string `json:"method"`
		URL          string `json:"url"`
		Host         string `json:"host"`
		Protocol     string `json:"protocol,omitempty"`
		StatusCode   int    `json:"statusCode"`
		ContentType  string `json:"contentType"`
		DurationMs   int64  `json:"durationMs"`
		ResponseSize int    `json:"responseSize"`
	}

	summaries := make([]summary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, summary{
			ID:           item.ID,
			Seq:          item.Seq,
			Timestamp:    item.Timestamp.Format("2006-01-02T15:04:05.000Z"),
			Method:       item.Method,
			URL:          item.URL,
			Host:         item.Host,
			Protocol:     item.Protocol,
			StatusCode:   item.StatusCode,
			ContentType:  item.ContentType,
			DurationMs:   item.Duration.Milliseconds(),
			ResponseSize: item.ResponseSize,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":  summaries,
		"total":  total,
		"offset": f.Offset,
		"limit":  f.Limit,
	})
}

func (s *APIServer) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	item := s.store.Get(id)
	if item == nil {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id": item.ID,
		// Seq is the handle every server-side feature addresses a capture by, and
		// the client's RequestDetail has always been typed as carrying it — it
		// extends RequestSummary, which the list endpoint does fill in. Omitting
		// it here made that type a lie no compiler could catch: a caller reading
		// detail.seq got undefined, which JSON-encodes to null and decodes in Go
		// as 0, and the request was reported as evicted from the capture buffer.
		"seq":          item.Seq,
		"timestamp":    item.Timestamp.Format("2006-01-02T15:04:05.000Z"),
		"method":       item.Method,
		"url":          item.URL,
		"host":         item.Host,
		"protocol":     item.Protocol,
		"statusCode":   item.StatusCode,
		"contentType":  item.ContentType,
		"durationMs":   item.Duration.Milliseconds(),
		"responseSize": item.ResponseSize,
		"reqRaw":       base64.StdEncoding.EncodeToString(item.ReqRaw),
		"respRaw":      base64.StdEncoding.EncodeToString(item.RespRaw),
	})
}

// handleGetRequestParams lists every input one captured request carried — query,
// path segment, form field, JSON leaf, multipart field, cookie and header — as
// the one walker in the repo enumerates them. It is the per-request half of the
// site-map inventory and, like it, runs on demand and needs nothing from the
// reflection engine.
func (s *APIServer) handleGetRequestParams(w http.ResponseWriter, r *http.Request) {
	item := s.store.Get(r.PathValue("id"))
	if item == nil {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}

	cfg := echo.DefaultConfig()
	if s.echoEngine != nil {
		cfg = s.echoEngine.Config()
	}
	cfg.Normalize()
	params := echo.RequestParams(item, cfg)

	writeJSON(w, http.StatusOK, map[string]any{
		"requestId": item.ID,
		"params":    params,
		// The walker stops at MaxValuesPerRequest without saying it did, so a full
		// slice is the only signal available. A request carrying exactly the cap
		// reports truncated, which is the safe direction to be wrong in.
		"truncated": len(params) >= cfg.MaxValuesPerRequest,
	})
}

func (s *APIServer) handleClearRequests(w http.ResponseWriter, r *http.Request) {
	s.store.Clear()
	// Clear zeroes the store's sequence counter, so the detection cursor must be
	// reset with it.
	s.resetDetectCursor(0)
	s.clearDetectFindingsWithHistory()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}
