package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/detect"
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

	// Template-signature rule options. Tags and Severity narrow which signatures
	// run; IgnoreFingerprint skips technology gating and runs every eligible one.
	Tags              []string `json:"tags,omitempty"`
	Severity          []string `json:"severity,omitempty"`
	IgnoreFingerprint bool     `json:"ignoreFingerprint,omitempty"`
	// OAST opts out-of-band testing in or out when a listener is configured; nil
	// (omitted) leaves it on, false turns it off. It never enables OAST when no
	// callback domain is configured — that gate is server-side.
	OAST *bool `json:"oast,omitempty"`
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
		Scope:             req.Scope,
		Rules:             req.Rules,
		BudgetMs:          req.BudgetMs,
		Tags:              req.Tags,
		Severity:          req.Severity,
		IgnoreFingerprint: req.IgnoreFingerprint,
		NoOAST:            req.OAST != nil && !*req.OAST,
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
			Tech:      s.techStore(),
			Callback:  s.cbStore,
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

// hostTarget collects a host's distinct requests from the capture store, carrying
// the raw bytes and method so the injection rules can fuzz parameters (GET query +
// POST/PUT/PATCH bodies) and DOM XSS can navigate the GET pages. Distinct by
// method+URL+body-shape, so two POSTs to one URL with different bodies both count.
// Not capped by a request count — the scan budget bounds the work.
func (s *APIServer) hostTarget(origin string) (activescan.Target, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return activescan.Target{}, fmt.Errorf("invalid origin")
	}
	reqs := s.store.NodeRequests(origin, "", false, proxy.RequestFilter{})
	seen := map[string]bool{}
	var urls []activescan.TargetURL
	for _, cr := range reqs {
		key := fmt.Sprintf("%s %s %d", cr.Method, cr.URL, len(cr.ReqRaw))
		if seen[key] {
			continue
		}
		seen[key] = true
		urls = append(urls, activescan.TargetURL{URL: cr.URL, Method: cr.Method, RequestID: cr.ID, RawReq: cr.ReqRaw})
	}
	if len(urls) == 0 {
		return activescan.Target{}, fmt.Errorf("no captured endpoints for %s", origin)
	}
	return activescan.Target{Scheme: u.Scheme, Host: u.Host, Origin: origin, URLs: urls}, nil
}

// requestTarget builds a single-request target from a captured request or a raw
// URL, carrying the raw bytes and method for the injection rules.
func (s *APIServer) requestTarget(req activeScanRequest) (activescan.Target, error) {
	rawURL := strings.TrimSpace(req.URL)
	method := "GET"
	requestID := ""
	var rawReq []byte
	if req.RequestID != "" {
		cr := s.store.Get(req.RequestID)
		if cr == nil {
			return activescan.Target{}, fmt.Errorf("no such request")
		}
		rawURL = cr.URL
		requestID = cr.ID
		method = cr.Method
		rawReq = cr.ReqRaw
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
		URLs:   []activescan.TargetURL{{URL: rawURL, Method: method, RequestID: requestID, RawReq: rawReq}},
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
		method := tu.Method
		if method == "" {
			method = "GET"
		}
		if s.scope.InScope(u.Host, method, u.Path) {
			kept = append(kept, tu)
		} else {
			skipped++
		}
	}
	return kept, skipped
}

// activeRuleSeverity is the representative severity shown for a single-row active
// rule in the Rules UI; the actual findings carry their own confirmed severity.
func activeRuleSeverity(cat detect.Category) detect.Severity {
	switch cat {
	case detect.CategorySQLi, detect.CategorySSTI, detect.CategoryCommandInjection:
		return detect.SeverityCritical
	case detect.CategoryOpenRedirect:
		return detect.SeverityMedium
	default:
		return detect.SeverityHigh
	}
}

func (s *APIServer) handleActiveScanRules(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	rules := s.activeScanRules.All()
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		entry := map[string]any{
			"id": rule.ID(), "name": rule.Name(), "category": string(rule.Category()),
			"description": rule.Description(),
			"enabled":     s.activeScanRules.IsEnabled(rule.ID()),
		}
		// hasSignatures tells the UI to render the rule's catalog items as rows rather
		// than the rule as a single row: any rule implementing Cataloger has a catalog.
		_, hasCatalog := rule.(activescan.Cataloger)
		entry["hasSignatures"] = hasCatalog
		// A single-row rule carries the row's severity/confidence/target (its
		// representative class severity); a catalog rule's rows carry their own.
		if !hasCatalog {
			entry["severity"] = string(activeRuleSeverity(rule.Category()))
			entry["confidence"] = string(detect.ConfidenceHigh)
			entry["target"] = string(detect.TargetMessage)
		}
		out = append(out, entry)
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

// collectDisabledItems gathers every catalog rule's disabled item ids, keyed by rule
// id, for the project file. Returns nil when nothing is disabled (exceptions-only).
func (s *APIServer) collectDisabledItems() map[string][]string {
	if s.activeScanRules == nil {
		return nil
	}
	out := map[string][]string{}
	for _, rule := range s.activeScanRules.All() {
		if c, ok := rule.(activescan.Cataloger); ok {
			if d := c.DisabledItems(); len(d) > 0 {
				out[rule.ID()] = d
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// applyDisabledItems distributes a rule-keyed disabled-items map back onto the catalog
// rules on a project restore; a missing key clears that rule's set (everything enabled).
func (s *APIServer) applyDisabledItems(m map[string][]string) {
	if s.activeScanRules == nil {
		return
	}
	for _, rule := range s.activeScanRules.All() {
		if c, ok := rule.(activescan.Cataloger); ok {
			c.SetDisabledItems(m[rule.ID()])
		}
	}
}

// disabledItemsSignature fingerprints every catalog rule's disabled set for the
// autosave dirty-check (registration order is stable, so the string is deterministic).
func (s *APIServer) disabledItemsSignature() string {
	if s.activeScanRules == nil {
		return ""
	}
	var b strings.Builder
	for _, rule := range s.activeScanRules.All() {
		if c, ok := rule.(activescan.Cataloger); ok {
			b.WriteString("/ci:" + rule.ID() + ":" + strings.Join(c.DisabledItems(), ","))
		}
	}
	return b.String()
}

// catalogRule returns the rule with the given id as a Cataloger, or nil if the rule
// does not exist or has no catalog. It replaces the old templatesig-specific resolver,
// so any catalog rule (template signatures, the injection rules) works generically.
func (s *APIServer) catalogRule(id string) activescan.Cataloger {
	if s.activeScanRules == nil {
		return nil
	}
	c, _ := s.activeScanRules.Get(id).(activescan.Cataloger)
	return c
}

// handleActiveScanSignatures returns a rule's read-only catalog — one item per
// signature or check, with its enabled-state and per-severity counts.
func (s *APIServer) handleActiveScanSignatures(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	rule := s.catalogRule(r.PathValue("id"))
	if rule == nil {
		writeError(w, http.StatusNotFound, "no catalog for this rule")
		return
	}
	items := rule.CatalogItems()
	bySeverity := map[string]int{}
	for i := range items {
		bySeverity[items[i].Severity]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"signatures": items, "total": len(items), "bySeverity": bySeverity,
	})
}

// handleSetActiveScanSignaturesBulk enables or disables every item of a rule's
// catalog in one call — the "Enable all / Disable all" control.
func (s *APIServer) handleSetActiveScanSignaturesBulk(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	rule := s.catalogRule(r.PathValue("id"))
	if rule == nil {
		writeError(w, http.StatusNotFound, "no catalog for this rule")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Enabled {
		rule.SetDisabledItems(nil)
	} else {
		items := rule.CatalogItems()
		ids := make([]string, 0, len(items))
		for i := range items {
			ids = append(ids, items[i].ID)
		}
		rule.SetDisabledItems(ids)
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled})
}

// handleSetActiveScanSignatureEnabled toggles one catalog item of a rule. Rule-scoped
// because check ids (e.g. "time-based") can repeat across rules. Persists with the
// project (projectSignature carries the disabled set), like the rule toggle.
func (s *APIServer) handleSetActiveScanSignatureEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.activeScanAvailable(w) {
		return
	}
	rule := s.catalogRule(r.PathValue("id"))
	if rule == nil {
		writeError(w, http.StatusNotFound, "no catalog for this rule")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	rule.SetItemEnabled(r.PathValue("itemId"), body.Enabled)
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
