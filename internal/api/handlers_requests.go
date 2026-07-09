package api

import (
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleListRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))

	status, _ := strconv.Atoi(q.Get("status"))

	extMode := q.Get("extMode")
	if extMode == "" {
		extMode = "exclude"
	}

	f := proxy.RequestFilter{
		Host:         q.Get("host"),
		Method:       q.Get("method"),
		Status:       status,
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
		"offset": offset,
		"limit":  limit,
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
		"id":           item.ID,
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

func (s *APIServer) handleClearRequests(w http.ResponseWriter, r *http.Request) {
	s.store.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}
