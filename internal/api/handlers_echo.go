package api

import (
	"net/http"
	"strconv"

	"github.com/BishopFox/joro/internal/echo"
)

// echoAvailable rejects requests when reflection mapping is not wired, as in
// listener and team-server mode. The routes are also behind the proxy-mode gate
// in registerRoutes.
func (s *APIServer) echoAvailable(w http.ResponseWriter) bool {
	if s.echoEngine == nil || s.echoStore == nil {
		writeError(w, http.StatusNotFound, "reflection mapping is unavailable in this mode")
		return false
	}
	return true
}

// handleGetEcho returns everything the tab needs on mount.
func (s *APIServer) handleGetEcho(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	cfg := s.echoEngine.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": cfg.Enabled,
		"config":  cfg,
		"summary": s.echoStore.Summary(),
		"hosts":   s.echoStore.Hosts(),
		"scan":    s.echoEngine.Status(),
	})
}

func (s *APIServer) handleSetEchoEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.echoEngine.SetEnabled(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled})
}

func (s *APIServer) handleGetEchoConfig(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.echoEngine.Config())
}

// echoConfigPatch is a pointer per field so a PUT can carry any subset, as
// detectConfigPatch does.
type echoConfigPatch struct {
	Enabled                  *bool     `json:"enabled"`
	ScopeOnly                *bool     `json:"scopeOnly"`
	MaxBodyScanBytes         *int      `json:"maxBodyScanBytes"`
	MaxRequestBodyScanBytes  *int      `json:"maxRequestBodyScanBytes"`
	MinValueLen              *int      `json:"minValueLen"`
	MaxValuesPerRequest      *int      `json:"maxValuesPerRequest"`
	MaxReflectionsPerRequest *int      `json:"maxReflectionsPerRequest"`
	TransformDepth           *int      `json:"transformDepth"`
	Base64                   *bool     `json:"base64"`
	ScanHeaders              *bool     `json:"scanHeaders"`
	ExcludeHosts             *[]string `json:"excludeHosts"`
}

func (s *APIServer) handleSetEchoConfig(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	var p echoConfigPatch
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cfg := s.echoEngine.Config()
	setBool(&cfg.Enabled, p.Enabled)
	setBool(&cfg.ScopeOnly, p.ScopeOnly)
	setInt(&cfg.MaxBodyScanBytes, p.MaxBodyScanBytes)
	setInt(&cfg.MaxRequestBodyScanBytes, p.MaxRequestBodyScanBytes)
	setInt(&cfg.MinValueLen, p.MinValueLen)
	setInt(&cfg.MaxValuesPerRequest, p.MaxValuesPerRequest)
	setInt(&cfg.MaxReflectionsPerRequest, p.MaxReflectionsPerRequest)
	setInt(&cfg.TransformDepth, p.TransformDepth)
	setBool(&cfg.Base64, p.Base64)
	setBool(&cfg.ScanHeaders, p.ScanHeaders)
	if p.ExcludeHosts != nil {
		cfg.ExcludeHosts = *p.ExcludeHosts
	}
	s.echoEngine.SetConfig(cfg)
	writeJSON(w, http.StatusOK, s.echoEngine.Config())
}

func setBool(dst *bool, v *bool) {
	if v != nil {
		*dst = *v
	}
}

func setInt(dst *int, v *int) {
	if v != nil {
		*dst = *v
	}
}

// handleListEchoParams returns a page of the map.
func (s *APIServer) handleListEchoParams(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	q := r.URL.Query()
	f := echo.Filter{
		Host:         q.Get("host"),
		Sources:      splitCSV(q.Get("source")),
		Contexts:     splitCSV(q.Get("context")),
		Transforms:   splitCSV(q.Get("transform")),
		BreakoutOnly: q.Get("breakout") == "true",
		Search:       q.Get("search"),
		Sort:         q.Get("sort"),
		Dir:          q.Get("dir"),
		Limit:        100,
	}
	if v, err := strconv.Atoi(q.Get("offset")); err == nil && v >= 0 {
		f.Offset = v
	}
	if q.Has("limit") {
		if v, err := strconv.Atoi(q.Get("limit")); err == nil {
			f.Limit = v
		}
	}
	items, total := s.echoStore.List(f)
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "offset": f.Offset, "limit": f.Limit,
	})
}

// handleGetEchoParam returns one row with its recent reflections.
func (s *APIServer) handleGetEchoParam(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	e, ok := s.echoStore.Entry(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no such parameter")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// handleGetEchoRequest returns one message's report, for the History pane. A
// request with no report is not an error: it may predate the feature being
// switched on, which the empty report says plainly.
func (s *APIServer) handleGetEchoRequest(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	id := r.PathValue("requestId")
	rep, ok := s.echoStore.Report(id)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"requestId": id, "analyzed": false, "reflections": []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requestId": id, "analyzed": true, "report": rep,
	})
}

func (s *APIServer) handleClearEcho(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	s.echoStore.Clear()
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

// handleStartEchoScan backfills the map from captured history. This is the
// common path: the feature is switched on after the interesting traffic has
// already been captured.
func (s *APIServer) handleStartEchoScan(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	var req echo.RescanRequest
	if err := decodeJSONOptional(r, &req, maxJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	status, err := s.echoEngine.StartRescan(s.detectBackgroundCtx(), req)
	if err == echo.ErrScanRunning {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) handleGetEchoScan(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.echoEngine.Status())
}

func (s *APIServer) handleCancelEchoScan(w http.ResponseWriter, r *http.Request) {
	if !s.echoAvailable(w) {
		return
	}
	s.echoEngine.Cancel()
	writeJSON(w, http.StatusOK, s.echoEngine.Status())
}
