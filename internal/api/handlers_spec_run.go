package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/apiscan"
	"github.com/BishopFox/joro/internal/apispec"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

// specScanRequest starts a scan or an auth matrix. The two differ only in how
// many profiles are named — a scan is a matrix with one.
type specScanRequest struct {
	SpecID       string   `json:"specId"`
	OperationIDs []string `json:"operationIds"`
	ProfileIDs   []string `json:"profileIds"`

	ServerIndex *int    `json:"serverIndex,omitempty"`
	Scheme      string  `json:"scheme,omitempty"`
	Host        string  `json:"host,omitempty"`
	BasePath    *string `json:"basePath,omitempty"`

	Values map[string]map[string]string `json:"values,omitempty"` // opID -> values

	Concurrency int     `json:"concurrency"`
	RatePerSec  float64 `json:"ratePerSec"`
	TimeoutMs   int     `json:"timeoutMs"`
	BudgetMs    int     `json:"budgetMs"`
	UserAgent   string  `json:"userAgent"`

	AllowDestructive bool     `json:"allowDestructive"`
	Methods          []string `json:"methods,omitempty"`
}

func (s *APIServer) handleSpecScanStart(w http.ResponseWriter, r *http.Request) {
	var req specScanRequest
	if err := decodeJSONLimit(r, &req, maxBulkJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	stored := s.specStore.Get(req.SpecID)
	if stored == nil {
		writeError(w, http.StatusNotFound, "no such document")
		return
	}

	ops := selectOperations(stored.Spec, req.OperationIDs)
	if len(ops) == 0 {
		writeError(w, http.StatusBadRequest, "no operations selected")
		return
	}

	profiles, err := s.selectProfiles(req.SpecID, req.ProfileIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	srv := serverFor(stored.Spec, req.ServerIndex, req.Scheme, req.Host, req.BasePath)
	if srv.Host == "" {
		writeError(w, http.StatusBadRequest,
			"no target host: the document declares no server, so scheme and host must be supplied")
		return
	}

	kind := apiscan.KindScan
	if len(profiles) > 1 {
		kind = apiscan.KindMatrix
	}

	values := map[string]apispec.Values{}
	for opID, v := range req.Values {
		values[opID] = apispec.Values(v)
	}

	cfg := apiscan.Config{
		Kind: kind, SpecID: req.SpecID, Server: srv, Ops: ops, Profiles: profiles, Values: values,
		Concurrency: req.Concurrency, RatePerSec: req.RatePerSec,
		TimeoutMs: req.TimeoutMs, BudgetMs: req.BudgetMs, UserAgent: req.UserAgent,
		AllowDestructive: req.AllowDestructive, Methods: normalizeMethods(req.Methods),
	}

	total, err := apiscan.Plan(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	run := apiscan.NewRun(proxy.GenerateID(), cfg, total)
	s.specRuns.Add(run)

	deps := apiscan.Deps{Send: s.specSendDeps(), Broadcast: s.hub.Broadcast()}
	go apiscan.Execute(context.Background(), run, deps)

	writeJSON(w, http.StatusCreated, map[string]any{
		"runId": run.ID, "kind": string(kind), "total": total,
		"warnings": s.runWarnings(total),
	})
}

// specDiscoverRequest starts a document sweep against a host.
type specDiscoverRequest struct {
	Scheme      string  `json:"scheme"`
	Host        string  `json:"host"`
	BasePath    string  `json:"basePath"`
	Full        bool    `json:"full"`
	StopOnFirst bool    `json:"stopOnFirst"`
	Concurrency int     `json:"concurrency"`
	RatePerSec  float64 `json:"ratePerSec"`
	TimeoutMs   int     `json:"timeoutMs"`
	BudgetMs    int     `json:"budgetMs"`
	UserAgent   string  `json:"userAgent"`
}

func (s *APIServer) handleSpecDiscoverStart(w http.ResponseWriter, r *http.Request) {
	var req specDiscoverRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	set := apispec.CandidatePriority
	if req.Full {
		set = apispec.CandidateFull
	}
	cfg := apiscan.Config{
		Kind: apiscan.KindDiscovery, Scheme: strings.ToLower(req.Scheme), Host: req.Host,
		BasePath: req.BasePath, CandidateSet: set, StopOnFirst: req.StopOnFirst,
		Concurrency: req.Concurrency, RatePerSec: req.RatePerSec,
		TimeoutMs: req.TimeoutMs, BudgetMs: req.BudgetMs, UserAgent: req.UserAgent,
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "https"
	}

	paths, err := apiscan.PlanDiscovery(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	run := apiscan.NewRun(proxy.GenerateID(), cfg, len(paths))
	s.specRuns.Add(run)

	deps := apiscan.Deps{Send: s.specSendDeps(), Broadcast: s.hub.Broadcast()}
	// A document found mid-sweep is loaded straight into the store, so the
	// operator can switch to it without a second fetch.
	//
	// Only when it is not already held. A sweep parses with default placeholders,
	// so re-finding bytes the operator has since set a placeholder on would
	// silently revert their parse under the same ID. If it is already stored,
	// switching to it already works, which is all this Put was for.
	onSpec := func(spec *apispec.Spec, source []byte) {
		if s.specStore.Get(spec.ID) == nil {
			s.specStore.Put(spec, source)
		}
		s.hub.Broadcast() <- event.WSEvent{Type: "spec.run.found", Data: map[string]any{
			"runId": run.ID, "specId": spec.ID, "title": spec.Title,
			"format": string(spec.Format), "operations": len(spec.Operations),
			"sourceUrl": spec.SourceURL,
		}}
	}
	go apiscan.Discover(context.Background(), run, paths, deps, onSpec)

	writeJSON(w, http.StatusCreated, map[string]any{
		"runId": run.ID, "kind": string(apiscan.KindDiscovery), "total": len(paths),
		"warnings": s.runWarnings(len(paths)),
	})
}

func (s *APIServer) handleSpecListRuns(w http.ResponseWriter, r *http.Request) {
	runs := s.specRuns.List()
	out := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		completed, errs, skipped, hits := run.Counts()
		out = append(out, map[string]any{
			"id": run.ID, "kind": string(run.Kind), "specId": run.SpecID,
			"status": string(run.Status()), "total": run.Total,
			"completed": completed, "errors": errs, "skipped": skipped, "hits": hits,
			"createdAt": run.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}

func (s *APIServer) handleSpecGetRun(w http.ResponseWriter, r *http.Request) {
	run := s.specRuns.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	results := run.Results()
	offset, limit := pageParams(r, len(results))
	// Materialized, never nil: a nil slice marshals as null against a client type
	// that says array. See apispec.Spec.normalize.
	page := []apiscan.Result{}
	if offset < len(results) {
		end := min(offset+limit, len(results))
		page = results[offset:end]
	}

	completed, errs, skipped, hits := run.Counts()
	writeJSON(w, http.StatusOK, map[string]any{
		"id": run.ID, "kind": string(run.Kind), "specId": run.SpecID,
		"status": string(run.Status()), "total": run.Total,
		"completed": completed, "errors": errs, "skipped": skipped, "hits": hits,
		"createdAt": run.CreatedAt,
		"results":   page, "resultTotal": len(results), "offset": offset, "limit": limit,
	})
}

func (s *APIServer) handleSpecGetMatrix(w http.ResponseWriter, r *http.Request) {
	run := s.specRuns.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	if run.Kind == apiscan.KindDiscovery {
		writeError(w, http.StatusBadRequest, "a discovery run has no auth matrix")
		return
	}
	writeJSON(w, http.StatusOK, apiscan.Matrix(run))
}

// handleSpecGetResult returns one result including its raw bytes, fetched on
// demand rather than streamed, as the fuzzer's detail endpoint is.
func (s *APIServer) handleSpecGetResult(w http.ResponseWriter, r *http.Request) {
	run := s.specRuns.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "index must be a number")
		return
	}
	res, ok := run.ResultAt(idx)
	if !ok {
		writeError(w, http.StatusNotFound, "no such result")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result":  stripRaw(res),
		"reqRaw":  base64.StdEncoding.EncodeToString(res.ReqRaw),
		"respRaw": base64.StdEncoding.EncodeToString(res.RespRaw),
	})
}

func (s *APIServer) handleSpecStopRun(w http.ResponseWriter, r *http.Request) {
	run := s.specRuns.Get(r.PathValue("id"))
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

func (s *APIServer) handleSpecDeleteRun(w http.ResponseWriter, r *http.Request) {
	run := s.specRuns.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	if run.Status() == apiscan.StatusRunning {
		writeError(w, http.StatusConflict, "stop the run before deleting it")
		return
	}
	s.specRuns.Delete(run.ID)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// runWarnings reports conditions the operator should know about before a run
// rather than discover during one.
func (s *APIServer) runWarnings(total int) []string {
	out := []string{}
	// Every send goes through Joro's own proxy, so an armed intercept pauses each
	// one in the operator's queue. At scan volumes that is not a small surprise.
	if s.settings.InterceptEnabled {
		out = append(out, fmt.Sprintf(
			"request intercept is armed, so all %d requests will pause in the Intercept queue", total))
	}
	if total > 500 {
		out = append(out, fmt.Sprintf(
			"%d requests will be captured into History, which may evict older traffic from the capture buffer", total))
	}
	return out
}

func stripRaw(res apiscan.Result) apiscan.Result {
	res.ReqRaw, res.RespRaw = nil, nil
	return res
}

// selectOperations picks the named operations, preserving document order so a
// results table reads the way the tree does. An empty list means all of them.
func selectOperations(spec *apispec.Spec, ids []string) []apispec.Operation {
	if len(ids) == 0 {
		out := make([]apispec.Operation, len(spec.Operations))
		copy(out, spec.Operations)
		return out
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []apispec.Operation
	for _, op := range spec.Operations {
		if want[op.ID] {
			out = append(out, op)
		}
	}
	return out
}

// selectProfiles resolves the named profiles.
//
// Asking for nothing falls back to one unauthenticated profile, which is what
// makes a plain scan a matrix with one profile rather than a separate code path.
// Asking for profiles that do not resolve must not reach that fallback: ids are
// renumbered on re-save, so a stale request is ordinary, and running a
// credentialed matrix anonymously reports every reachable endpoint as open.
func (s *APIServer) selectProfiles(specID string, ids []string) ([]apiscan.Profile, error) {
	all := s.specStore.Profiles(specID)
	if len(ids) == 0 {
		if len(all) == 0 {
			return []apiscan.Profile{{ID: "none", Label: "unauthenticated", Rank: 0}}, nil
		}
		return all, nil
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []apiscan.Profile
	for _, p := range all {
		if want[p.ID] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("none of the requested auth profiles exist on this document; re-pick them")
	}
	if len(out) < len(ids) {
		return nil, fmt.Errorf("%d of the %d requested auth profiles no longer exist on this document; re-pick them",
			len(ids)-len(out), len(ids))
	}
	return out, nil
}

func serverFor(spec *apispec.Spec, index *int, scheme, host string, basePath *string) apispec.Server {
	srv := apispec.Server{}
	idx := 0
	if index != nil {
		idx = *index
	}
	if idx >= 0 && idx < len(spec.Servers) {
		srv = spec.Servers[idx]
	}
	if scheme != "" {
		srv.Scheme = scheme
	}
	if host != "" {
		srv.Host = host
	}
	if basePath != nil {
		srv.BasePath = *basePath
	}
	return srv
}

// normalizeMethods upper-cases a supplied whitelist. An empty one leaves the
// default, which excludes DELETE and PATCH.
func normalizeMethods(methods []string) []string {
	if len(methods) == 0 {
		return nil
	}
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			out = append(out, m)
		}
	}
	return out
}

func pageParams(r *http.Request, total int) (offset, limit int) {
	limit = 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return offset, limit
}
