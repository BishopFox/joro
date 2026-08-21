package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/event"
)

// detectAvailable rejects requests when detection is not wired, as in listener
// and team-server mode. The routes are also behind the proxy-mode gate in
// registerRoutes.
func (s *APIServer) detectAvailable(w http.ResponseWriter) bool {
	if s.detectEngine == nil || s.detectFindings == nil || s.detectScanner == nil {
		writeError(w, http.StatusNotFound, "detection is unavailable in this mode")
		return false
	}
	return true
}

// ruleEnabledFunc returns a predicate for filtering findings by whether their
// rule is currently switched on. Findings from a disabled rule are retained,
// not deleted.
func (s *APIServer) ruleEnabledFunc() func(string) bool {
	return s.detectEngine.RuleEnabledFunc()
}

// handleGetDetect returns the overall detection state for the page header.
func (s *APIServer) handleGetDetect(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	rules := s.detectEngine.Rules()
	active := 0
	for _, rule := range rules {
		if rule.Enabled {
			active++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     s.detectEngine.IsEnabled(),
		"config":      s.detectEngine.Config(),
		"summary":     s.detectFindings.Summary(s.ruleEnabledFunc()),
		"scan":        s.detectScanner.Status(),
		"cursor":      s.detectScanner.Cursor(),
		"ruleCount":   len(rules),
		"activeRules": active,
	})
}

// handleSetDetectEnabled toggles passive detection.
func (s *APIServer) handleSetDetectEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.detectEngine.SetEnabled(body.Enabled)
	if body.Enabled {
		// Catch up on anything captured while detection was off.
		s.detectScanner.Wake()
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled})
}

// handleGetDetectConfig returns the engine configuration.
func (s *APIServer) handleGetDetectConfig(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.detectEngine.Config())
}

// detectConfigPatch mirrors detect.Config with pointer fields so a PUT can carry
// any subset without zeroing the rest.
type detectConfigPatch struct {
	ScopeOnly                *bool     `json:"scopeOnly"`
	ScanRequests             *bool     `json:"scanRequests"`
	PersistFindings          *bool     `json:"persistFindings"`
	ClearFindingsWithHistory *bool     `json:"clearFindingsWithHistory"`
	MaxBodyScanBytes         *int      `json:"maxBodyScanBytes"`
	MaxRequestBodyScanBytes  *int      `json:"maxRequestBodyScanBytes"`
	SkipContentTypes         *[]string `json:"skipContentTypes"`
	SkipExtensions           *[]string `json:"skipExtensions"`
	ExcludeHosts             *[]string `json:"excludeHosts"`
}

// handleSetDetectConfig applies a partial configuration update.
func (s *APIServer) handleSetDetectConfig(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var patch detectConfigPatch
	if err := decodeJSON(r, &patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cfg := s.detectEngine.Config()
	if patch.ScopeOnly != nil {
		cfg.ScopeOnly = *patch.ScopeOnly
	}
	if patch.ScanRequests != nil {
		cfg.ScanRequests = *patch.ScanRequests
	}
	if patch.PersistFindings != nil {
		cfg.PersistFindings = *patch.PersistFindings
	}
	if patch.ClearFindingsWithHistory != nil {
		cfg.ClearFindingsWithHistory = *patch.ClearFindingsWithHistory
	}
	if patch.MaxBodyScanBytes != nil {
		cfg.MaxBodyScanBytes = *patch.MaxBodyScanBytes
	}
	if patch.MaxRequestBodyScanBytes != nil {
		cfg.MaxRequestBodyScanBytes = *patch.MaxRequestBodyScanBytes
	}
	if patch.SkipContentTypes != nil {
		cfg.SkipContentTypes = *patch.SkipContentTypes
	}
	if patch.SkipExtensions != nil {
		cfg.SkipExtensions = *patch.SkipExtensions
	}
	if patch.ExcludeHosts != nil {
		cfg.ExcludeHosts = *patch.ExcludeHosts
	}
	s.detectEngine.SetConfig(cfg)
	writeJSON(w, http.StatusOK, s.detectEngine.Config())
}

// splitCSV parses a comma-separated query parameter, dropping empties.
func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// findingFilterFromQuery builds a filter from the query string.
func findingFilterFromQuery(r *http.Request) detect.FindingFilter {
	q := r.URL.Query()
	f := detect.FindingFilter{
		Severities:      splitCSV(q.Get("severity")),
		MinSeverity:     q.Get("minSeverity"),
		Categories:      splitCSV(q.Get("category")),
		RuleID:          q.Get("ruleId"),
		Host:            q.Get("host"),
		Search:          q.Get("search"),
		Confidence:      q.Get("confidence"),
		FP:              q.Get("fp"),
		IncludeDisabled: q.Get("includeDisabled") == "true",
		Sort:            q.Get("sort"),
		Dir:             q.Get("dir"),
		Limit:           100,
	}
	if v, err := strconv.Atoi(q.Get("offset")); err == nil && v >= 0 {
		f.Offset = v
	}
	if q.Has("limit") {
		if v, err := strconv.Atoi(q.Get("limit")); err == nil {
			// limit=0 means "all", consistent with the requests endpoint.
			f.Limit = v
		}
	}
	return f
}

// handleListFindings returns a filtered, paginated page of findings.
func (s *APIServer) handleListFindings(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	f := findingFilterFromQuery(r)
	items, total := s.detectFindings.List(f, s.ruleEnabledFunc())
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  detect.Summaries(items),
		"total":  total,
		"offset": f.Offset,
		"limit":  f.Limit,
	})
}

// handleGetFinding returns one finding with its occurrences. Each occurrence
// reports whether the referenced request is still in the ring buffer; the
// finding itself survives eviction, since its evidence is self-contained.
func (s *APIServer) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	f, ok := s.detectFindings.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}

	type occurrence struct {
		RequestID      string `json:"requestId"`
		Seq            int    `json:"seq"`
		Method         string `json:"method"`
		URL            string `json:"url"`
		StatusCode     int    `json:"statusCode"`
		Timestamp      string `json:"timestamp"`
		Offset         int    `json:"offset"`
		Part           string `json:"part"`
		RequestPresent bool   `json:"requestPresent"`
	}
	occs := make([]occurrence, 0, len(f.Occurrences))
	for _, o := range f.Occurrences {
		present := false
		if s.store != nil && o.RequestID != "" {
			present = s.store.Get(o.RequestID) != nil
		}
		occs = append(occs, occurrence{
			RequestID: o.RequestID, Seq: o.Seq, Method: o.Method, URL: o.URL,
			StatusCode: o.StatusCode, Timestamp: o.Timestamp.Format(timeFormat),
			Offset: o.Offset, Part: o.Part, RequestPresent: present,
		})
	}

	// Included so the detail pane can render description and remediation without
	// a second request.
	var rule any
	if rr, found := s.detectEngine.Rule(f.RuleID); found {
		rule = rr
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"finding":     detect.Summaries([]detect.Finding{f})[0],
		"notes":       f.Notes,
		"occurrences": occs,
		"rule":        rule,
	})
}

// timeFormat matches the format used by the history handlers.
const timeFormat = "2006-01-02T15:04:05.000Z"

// handleUpdateFinding applies operator triage: a false-positive mark, a note, or
// a severity override. Any subset may be supplied.
func (s *APIServer) handleUpdateFinding(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var body struct {
		FalsePositive *bool   `json:"falsePositive"`
		Notes         *string `json:"notes"`
		Severity      *string `json:"severity"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	var sev *detect.Severity
	if body.Severity != nil {
		v := detect.Severity(strings.ToLower(*body.Severity))
		if !v.Valid() {
			writeError(w, http.StatusBadRequest, "unknown severity")
			return
		}
		sev = &v
	}
	f, ok := s.detectFindings.Update(r.PathValue("id"), body.FalsePositive, body.Notes, sev)
	if !ok {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	s.broadcastDetectSummary()
	writeJSON(w, http.StatusOK, detect.Summaries([]detect.Finding{f})[0])
}

// handleDeleteFinding removes one finding.
func (s *APIServer) handleDeleteFinding(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if !s.detectFindings.Delete(id) {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	s.broadcastDetectSummary()
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// handleClearFindings deletes all findings, or only the false-positive ones when
// ?fp=true is supplied.
func (s *APIServer) handleClearFindings(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var n int
	if r.URL.Query().Get("fp") == "true" {
		n = s.detectFindings.DeleteFalsePositives()
	} else {
		n = s.detectFindings.Clear()
	}
	s.hub.Broadcast() <- event.WSEvent{
		Type: "detect.findings.cleared",
		Data: map[string]any{"deleted": n},
	}
	s.broadcastDetectSummary()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// broadcastDetectSummary pushes updated aggregate counts.
func (s *APIServer) broadcastDetectSummary() {
	if s.hub == nil || s.detectFindings == nil {
		return
	}
	s.hub.Broadcast() <- event.WSEvent{
		Type: "detect.summary",
		Data: s.detectFindings.Summary(s.ruleEnabledFunc()),
	}
}

// broadcastDetectRules notifies clients that the rule set changed.
func (s *APIServer) broadcastDetectRules() {
	if s.hub == nil || s.detectEngine == nil {
		return
	}
	rules := s.detectEngine.Rules()
	builtin, user, active := 0, 0, 0
	for _, r := range rules {
		if r.Builtin {
			builtin++
		} else {
			user++
		}
		if r.Enabled {
			active++
		}
	}
	s.hub.Broadcast() <- event.WSEvent{
		Type: "detect.rules.changed",
		Data: map[string]any{
			"builtinCount": builtin, "userCount": user, "activeCount": active,
		},
	}
}

// handleListDetectRules returns every rule, built-in and custom, as one list.
func (s *APIServer) handleListDetectRules(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	q := r.URL.Query()
	cats := splitCSV(q.Get("category"))
	sevs := splitCSV(q.Get("severity"))
	origin := q.Get("builtin")
	state := q.Get("enabled")
	search := strings.ToLower(q.Get("search"))

	all := s.detectRulesWithCounts()
	out := make([]detectRuleView, 0, len(all))
	builtin, user, active := 0, 0, 0
	for _, rule := range all {
		if rule.Builtin {
			builtin++
		} else {
			user++
		}
		if rule.Enabled {
			active++
		}
		if len(cats) > 0 && !containsFoldStr(cats, string(rule.Category)) {
			continue
		}
		if len(sevs) > 0 && !containsFoldStr(sevs, string(rule.Severity)) {
			continue
		}
		if origin == "true" && !rule.Builtin {
			continue
		}
		if origin == "false" && rule.Builtin {
			continue
		}
		if state == "true" && !rule.Enabled {
			continue
		}
		if state == "false" && rule.Enabled {
			continue
		}
		if search != "" &&
			!strings.Contains(strings.ToLower(rule.Name), search) &&
			!strings.Contains(strings.ToLower(rule.ID), search) &&
			!strings.Contains(strings.ToLower(rule.Description), search) {
			continue
		}
		out = append(out, rule)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rules":        out,
		"builtinCount": builtin,
		"userCount":    user,
		"activeCount":  active,
		"categories":   detect.AllCategories(),
		"postFilters":  detect.PostFilterNames(),
	})
}

// detectRuleView is a rule plus its current finding count.
type detectRuleView struct {
	detect.Rule
	FindingCount int `json:"findingCount"`
}

// detectRulesWithCounts joins the rule list with per-rule finding counts.
func (s *APIServer) detectRulesWithCounts() []detectRuleView {
	counts := map[string]int{}
	for _, f := range s.detectFindings.All() {
		counts[f.RuleID]++
	}
	rules := s.detectEngine.Rules()
	out := make([]detectRuleView, 0, len(rules))
	for _, r := range rules {
		out = append(out, detectRuleView{Rule: r, FindingCount: counts[r.ID]})
	}
	return out
}

// containsFoldStr reports whether list contains v, case-insensitively.
func containsFoldStr(list []string, v string) bool {
	for _, item := range list {
		if strings.EqualFold(item, v) {
			return true
		}
	}
	return false
}

// handleAddDetectRule creates a custom rule.
func (s *APIServer) handleAddDetectRule(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var rule detect.Rule
	if err := decodeJSON(r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	created, err := s.detectEngine.AddRule(rule)
	if err != nil {
		// Surface the RE2 error text verbatim.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.broadcastDetectRules()
	writeJSON(w, http.StatusCreated, created)
}

// handleUpdateDetectRule replaces a custom rule, preserving its ID. Unlike the
// other rule collections, delete-and-recreate is not equivalent here: the ID is
// referenced by every finding the rule produced.
func (s *APIServer) handleUpdateDetectRule(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var rule detect.Rule
	if err := decodeJSON(r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	updated, err := s.detectEngine.UpdateRule(r.PathValue("id"), rule)
	if err != nil {
		s.writeRuleError(w, err)
		return
	}
	s.broadcastDetectRules()
	writeJSON(w, http.StatusOK, updated)
}

// writeRuleError maps engine rule errors to status codes.
func (s *APIServer) writeRuleError(w http.ResponseWriter, err error) {
	switch err {
	case detect.ErrBuiltinImmutable:
		// Built-ins accept only an enabled toggle and a severity override.
		writeError(w, http.StatusForbidden, err.Error())
	case detect.ErrRuleNotFound:
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

// handleSetDetectRuleEnabled toggles any rule, built-in or custom.
func (s *APIServer) handleSetDetectRuleEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id := r.PathValue("id")
	if err := s.detectEngine.SetRuleEnabled(id, body.Enabled); err != nil {
		s.writeRuleError(w, err)
		return
	}
	s.broadcastDetectRules()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": body.Enabled})
}

// handleSetDetectRuleSeverity overrides a rule's severity. Allowed on built-ins.
func (s *APIServer) handleSetDetectRuleSeverity(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var body struct {
		Severity string `json:"severity"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id := r.PathValue("id")
	if err := s.detectEngine.SetRuleSeverity(id, detect.Severity(strings.ToLower(body.Severity))); err != nil {
		s.writeRuleError(w, err)
		return
	}
	s.broadcastDetectRules()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "severity": body.Severity})
}

// handleResetDetectRule clears operator overrides on a built-in rule.
func (s *APIServer) handleResetDetectRule(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.detectEngine.ResetRule(id); err != nil {
		s.writeRuleError(w, err)
		return
	}
	s.broadcastDetectRules()
	rule, _ := s.detectEngine.Rule(id)
	writeJSON(w, http.StatusOK, rule)
}

// handleDeleteDetectRule removes a custom rule.
func (s *APIServer) handleDeleteDetectRule(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.detectEngine.RemoveRule(id); err != nil {
		s.writeRuleError(w, err)
		return
	}
	s.broadcastDetectRules()
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// maxRuleTestSample bounds the pattern-tester input.
const maxRuleTestSample = 1 << 20

// handleTestDetectRule compiles a pattern and reports its matches against a
// sample, so a rule can be authored without live traffic.
func (s *APIServer) handleTestDetectRule(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var body struct {
		Pattern      string  `json:"pattern"`
		Sample       string  `json:"sample"`
		SampleB64    string  `json:"sampleB64"`
		CaptureGroup int     `json:"captureGroup"`
		MinEntropy   float64 `json:"minEntropy"`
		MinLength    int     `json:"minLength"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleTestSample*2)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	re, err := regexp.Compile(body.Pattern)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	sample := []byte(body.Sample)
	if body.SampleB64 != "" {
		if decoded, decErr := base64.StdEncoding.DecodeString(body.SampleB64); decErr == nil {
			sample = decoded
		}
	}
	truncated := false
	if len(sample) > maxRuleTestSample {
		sample = sample[:maxRuleTestSample]
		truncated = true
	}

	type match struct {
		Match    string  `json:"match"`
		Redacted string  `json:"redacted"`
		Offset   int     `json:"offset"`
		Length   int     `json:"length"`
		Entropy  float64 `json:"entropy"`
		Passes   bool    `json:"passes"`
	}
	const maxMatches = 50
	matches := make([]match, 0, 8)
	for _, loc := range re.FindAllSubmatchIndex(sample, maxMatches) {
		lo, hi := loc[0], loc[1]
		if g := body.CaptureGroup; g > 0 && 2*g+1 < len(loc) && loc[2*g] >= 0 {
			lo, hi = loc[2*g], loc[2*g+1]
		}
		raw := string(sample[lo:hi])
		entropy := detect.ShannonEntropy(raw)
		passes := true
		if body.MinLength > 0 && len(raw) < body.MinLength {
			passes = false
		}
		if body.MinEntropy > 0 && entropy < body.MinEntropy {
			passes = false
		}
		matches = append(matches, match{
			Match: raw, Redacted: detect.RedactValue(raw), Offset: lo,
			Length: hi - lo, Entropy: entropy, Passes: passes,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":     true,
		"groups":    re.NumSubexp(),
		"matches":   matches,
		"truncated": truncated,
	})
}

// handleStartDetectScan begins an on-demand rescan over captured traffic.
func (s *APIServer) handleStartDetectScan(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	var req detect.RescanRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
	}
	if req.Scope == "" {
		req.Scope = "all"
	}
	// Not r.Context(): the rescan outlives this request.
	status, err := s.detectScanner.StartRescan(s.detectBackgroundCtx(), req)
	if err == detect.ErrScanRunning {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, status)
}

// handleGetDetectScan reports rescan progress.
func (s *APIServer) handleGetDetectScan(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.detectScanner.Status())
}

// handleCancelDetectScan stops a running rescan.
func (s *APIServer) handleCancelDetectScan(w http.ResponseWriter, r *http.Request) {
	if !s.detectAvailable(w) {
		return
	}
	s.detectScanner.Cancel()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}
