package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/proxy"
)

// activeScanAvailable guards the active-scan routes, which exist only in proxy
// mode. A JSON 404 rather than an unregistered route, so the SPA catch-all does
// not answer with 200 + HTML.
func (s *APIServer) activeScanAvailable(w http.ResponseWriter) bool {
	if s.activeScans == nil || s.activeScanRules == nil {
		writeError(w, http.StatusNotFound, "active scanning is not available in this mode")
		return false
	}
	return true
}

// activeScanRequest starts a scan of a host or a single request.
type activeScanRequest struct {
	// Scope is "host" (every captured GET endpoint for Origin) or "request" (one
	// URL, from RequestID or URL).
	Scope     string   `json:"scope"`
	Origin    string   `json:"origin,omitempty"`    // scheme://host[:port], for a host scan
	URL       string   `json:"url,omitempty"`       // a single URL, e.g. from Manipulate
	RequestID string   `json:"requestId,omitempty"` // a captured request to scan
	Rules     []string `json:"rules,omitempty"`     // rule IDs; empty = all
	BudgetMs  int      `json:"budgetMs,omitempty"`
}

func (s *APIServer) handleActiveScanStart(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	var req activeScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	target, err := s.resolveScanTarget(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Scope filter, never a rule-count check: InScope returns true when scope
	// filtering is disabled, so with scope off nothing is rejected and the scan
	// covers every target. A host scan silently drops out-of-scope endpoints; a
	// single-request scan whose one URL is out of scope is refused outright so the
	// operator is not left with a silent, empty run.
	inScope, skipped := s.filterInScope(target.URLs)
	if len(inScope) == 0 {
		if req.Scope == "request" {
			writeError(w, http.StatusForbidden, "target is out of scope; adjust scope rules or disable scope filtering")
			return
		}
		writeError(w, http.StatusBadRequest, "no in-scope GET endpoints to scan for this host")
		return
	}
	target.URLs = inScope

	rules := s.activeScanRules.Resolve(req.Rules)
	cfg := activescan.Config{
		Scope:    req.Scope,
		Rules:    req.Rules,
		BudgetMs: req.BudgetMs,
	}
	total, err := activescan.Plan(cfg, target, rules)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ruleIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		ruleIDs = append(ruleIDs, rule.ID())
	}

	// One at a time, globally. A DOM XSS scan drives a single browser and a future
	// state-changing rule would race the target's own state; the claim and the
	// insert are one operation so two requests cannot both pass.
	run := activescan.NewRun(proxy.GenerateID(), cfg, target, ruleIDs, total)
	if running := s.activeScans.AddIfIdle(run); running != nil {
		writeError(w, http.StatusConflict,
			fmt.Sprintf("a scan of %q is already in flight; stop it before starting another", running.Origin))
		return
	}

	deps := activescan.Deps{
		Broadcast: s.hub.Broadcast(),
		Findings:  s.detectFindings,
		Notify:    s.broadcastDetectSummary,
		Registry:  s.activeScanRules,
		RuleDeps: activescan.RuleDeps{
			ProxyAddr: fmt.Sprintf("%s:%d", s.cfg.BindAddr, s.cfg.ProxyPort),
			CA:        s.ca,
			Store:     s.store,
			Scope:     s.scope,
			DataDir:   s.cfg.DataDir,
		},
	}
	// context.Background, not the request's: a scan outlives the HTTP call.
	go activescan.Execute(context.Background(), run, deps)

	writeJSON(w, http.StatusCreated, map[string]any{
		"runId": run.ID, "total": total, "rules": ruleIDs,
		"urls": len(target.URLs), "skipped": skipped,
	})
}

// resolveScanTarget turns a request into the concrete URLs to scan.
func (s *APIServer) resolveScanTarget(req activeScanRequest) (activescan.Target, error) {
	switch req.Scope {
	case "host":
		if req.Origin == "" {
			return activescan.Target{}, fmt.Errorf("origin is required for a host scan")
		}
		return s.hostTarget(req.Origin)
	case "request":
		return s.requestTarget(req)
	default:
		return activescan.Target{}, fmt.Errorf("scope must be \"host\" or \"request\"")
	}
}

// hostTarget collects a host's unique GET URLs from the capture store.
func (s *APIServer) hostTarget(origin string) (activescan.Target, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return activescan.Target{}, fmt.Errorf("invalid origin")
	}
	reqs := s.store.NodeRequests(origin, "", false, proxy.RequestFilter{})
	seen := map[string]bool{}
	var urls []activescan.TargetURL
	for _, cr := range reqs {
		if !strings.EqualFold(cr.Method, "GET") || seen[cr.URL] {
			continue
		}
		seen[cr.URL] = true
		urls = append(urls, activescan.TargetURL{URL: cr.URL, Method: "GET", RequestID: cr.ID})
		if len(urls) >= activescan.MaxURLs {
			break
		}
	}
	if len(urls) == 0 {
		return activescan.Target{}, fmt.Errorf("no captured GET endpoints for %s", origin)
	}
	return activescan.Target{Scheme: u.Scheme, Host: u.Host, Origin: origin, URLs: urls}, nil
}

// requestTarget builds a single-URL target from a captured request or a raw URL.
func (s *APIServer) requestTarget(req activeScanRequest) (activescan.Target, error) {
	rawURL := strings.TrimSpace(req.URL)
	requestID := ""
	if req.RequestID != "" {
		cr := s.store.Get(req.RequestID)
		if cr == nil {
			return activescan.Target{}, fmt.Errorf("no such request")
		}
		rawURL = cr.URL
		requestID = cr.ID
	}
	if rawURL == "" {
		return activescan.Target{}, fmt.Errorf("a request scan needs a requestId or url")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return activescan.Target{}, fmt.Errorf("invalid url")
	}
	return activescan.Target{
		Scheme: u.Scheme,
		Host:   u.Host,
		Origin: u.Scheme + "://" + u.Host,
		URLs:   []activescan.TargetURL{{URL: rawURL, Method: "GET", RequestID: requestID}},
	}, nil
}

// filterInScope keeps only URLs that pass scope, returning the kept set and the
// number dropped. With scope filtering disabled, InScope is true for all.
func (s *APIServer) filterInScope(urls []activescan.TargetURL) (kept []activescan.TargetURL, skipped int) {
	for _, tu := range urls {
		u, err := url.Parse(tu.URL)
		if err != nil {
			skipped++
			continue
		}
		if s.scope.InScope(u.Host, "GET", u.Path) {
			kept = append(kept, tu)
		} else {
			skipped++
		}
	}
	return kept, skipped
}

func (s *APIServer) handleActiveScanRules(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	rules := s.activeScanRules.All()
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"id": rule.ID(), "name": rule.Name(), "category": string(rule.Category()),
			"enabled": s.activeScanRules.IsEnabled(rule.ID()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

// handleSetActiveScanRuleEnabled toggles whether a rule runs when a scan is
// started without an explicit rule selection. The toggle persists with the
// project, so it marks the config dirty. Mirrors handleSetDetectRuleEnabled.
func (s *APIServer) handleSetActiveScanRuleEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if s.activeScanRules.Get(id) == nil {
		writeError(w, http.StatusNotFound, "no such rule")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.activeScanRules.SetEnabled(id, body.Enabled)
	// The toggle is picked up by the next autosave tick, which compares
	// projectSignature (now carrying the disabled set); no explicit save here.
	writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled})
}

func (s *APIServer) handleActiveScanListRuns(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	runs := s.activeScans.List()
	out := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		out = append(out, activeScanHead(run))
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}

func activeScanHead(run *activescan.Run) map[string]any {
	completed, errs, findings := run.Counts()
	return map[string]any{
		"id": run.ID, "host": run.Host, "origin": run.Origin, "scope": run.Scope,
		"rules": run.Rules, "status": string(run.Status()), "total": run.Total,
		"completed": completed, "errors": errs, "findings": findings,
		"createdAt": run.CreatedAt,
	}
}

func (s *APIServer) handleActiveScanGetRun(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	run := s.activeScans.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	body := activeScanHead(run)
	body["errorMessages"] = run.Errors()
	writeJSON(w, http.StatusOK, body)
}

func (s *APIServer) handleActiveScanStopRun(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	run := s.activeScans.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	if !run.Stop() {
		writeError(w, http.StatusConflict, "run is not running")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
}

func (s *APIServer) handleActiveScanDeleteRun(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	run := s.activeScans.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	if run.Status() == activescan.StatusRunning {
		writeError(w, http.StatusConflict, "stop the run before deleting it")
		return
	}
	s.activeScans.Delete(run.ID)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
