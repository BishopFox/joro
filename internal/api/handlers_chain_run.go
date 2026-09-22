package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/chain"
	"github.com/BishopFox/joro/internal/chainrun"
	"github.com/BishopFox/joro/internal/proxy"
)

// chainRunRequest starts a sweep. A single-variant run is a sweep of one, which
// is why there is one endpoint and one runner rather than two of each.
type chainRunRequest struct {
	ChainID string   `json:"chainId"`
	Kinds   []string `json:"kinds"`

	// VariantIDs narrows a sweep to specific variants, for re-running one row of
	// a grid without re-running the whole thing. The baseline is always included
	// regardless: it is the comparison basis, and a run without it has nothing
	// to compare against.
	VariantIDs []string `json:"variantIds,omitempty"`

	AllowStateChanging bool `json:"allowStateChanging"`
	DelayMs            int  `json:"delayMs"`
	TimeoutMs          int  `json:"timeoutMs"`
	BudgetMs           int  `json:"budgetMs"`
}

func (s *APIServer) handleChainRunStart(w http.ResponseWriter, r *http.Request) {
	var req chainRunRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	ch := s.chainStore.Get(req.ChainID)
	if ch == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}

	variants := chain.GenerateVariants(ch, req.Kinds)
	if len(req.VariantIDs) > 0 {
		variants = filterVariants(variants, req.VariantIDs)
	}

	cfg := chainrun.Config{
		ChainID:            ch.ID,
		Chain:              ch,
		Variants:           variants,
		AllowStateChanging: req.AllowStateChanging,
		DelayMs:            req.DelayMs,
		TimeoutMs:          req.TimeoutMs,
		BudgetMs:           req.BudgetMs,
	}

	total, err := chainrun.Plan(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// One at a time, globally. Two sweeps against one application interleave on
	// its own state and both produce verdicts describing the interleaving. This
	// refuses rather than queueing, because a queue would hide the constraint
	// behind a wait and the operator would never learn why it exists. The claim
	// and the insert are one operation, so two requests cannot both pass.
	run := chainrun.NewRun(proxy.GenerateID(), cfg, total)
	if running := s.chainRuns.AddIfIdle(run); running != nil {
		writeError(w, http.StatusConflict,
			fmt.Sprintf("a run of %q is already in flight; stop it before starting another", running.ChainName))
		return
	}

	deps := chainrun.Deps{Send: s.specSendDeps(), Broadcast: s.hub.Broadcast()}
	// context.Background, not the request's: a sweep outlives the HTTP call that
	// started it.
	go chainrun.Execute(context.Background(), run, deps)

	writeJSON(w, http.StatusCreated, map[string]any{
		"runId": run.ID, "total": total, "variants": len(variants),
		"warnings": s.chainRunWarnings(ch, variants, total),
	})
}

// filterVariants narrows a generated set, always keeping the baseline.
func filterVariants(all []chain.Variant, ids []string) []chain.Variant {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := make([]chain.Variant, 0, len(ids)+1)
	for _, v := range all {
		if v.Kind == chain.VariantBaseline || want[v.ID] {
			out = append(out, v)
		}
	}
	return out
}

// chainRunWarnings reports what a sweep is about to do, before it does it.
//
// The request count is the number an operator is surprised by: a seven-step
// checkout with three mutation kinds is not seven requests, it is most of a
// hundred, and a dozen of them are real POSTs to a payment endpoint.
func (s *APIServer) chainRunWarnings(ch *chain.Chain, variants []chain.Variant, total int) []string {
	out := []string{}

	if methods := chain.StateChangingMethods(ch); len(methods) > 0 {
		var targets []string
		seen := map[string]bool{}
		for _, st := range ch.Steps {
			m := chain.MethodOf(st.ReqRaw)
			if m == "" || m == "GET" || m == "HEAD" || m == "OPTIONS" {
				continue
			}
			key := m + " " + chain.TargetOf(st.ReqRaw)
			if !seen[key] {
				seen[key] = true
				targets = append(targets, st.Label)
			}
		}
		if len(targets) > 3 {
			targets = append(targets[:3], fmt.Sprintf("and %d more", len(targets)-3))
		}
		out = append(out, fmt.Sprintf(
			"%d variants will send %d requests, including %s to %s — each variant repeats these for real",
			len(variants), total, strings.Join(methods, "/"), strings.Join(targets, ", ")))
	} else {
		out = append(out, fmt.Sprintf("%d variants will send %d requests", len(variants), total))
	}

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

// handleChainPlan reports what a sweep would do without starting it, so the
// warnings and the request count can be shown beside the arming checkbox rather
// than only after the operator has committed.
func (s *APIServer) handleChainPlan(w http.ResponseWriter, r *http.Request) {
	ch := s.chainStore.Get(r.PathValue("id"))
	if ch == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	kinds := strings.Split(r.URL.Query().Get("kinds"), ",")
	variants := chain.GenerateVariants(ch, kinds)
	total, err := chain.Plan(ch, variants)

	resp := map[string]any{
		"variants": variants,
		"total":    total,
		"warnings": s.chainRunWarnings(ch, variants, total),
		"methods":  chain.StateChangingMethods(ch),
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleChainListRuns(w http.ResponseWriter, r *http.Request) {
	runs := s.chainRuns.List()
	out := make([]map[string]any, 0, len(runs))
	for _, run := range runs {
		out = append(out, chainRunHead(run))
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}

func chainRunHead(run *chainrun.Run) map[string]any {
	completed, errs, unresolved, bypassed := run.Counts()
	return map[string]any{
		"id": run.ID, "chainId": run.ChainID, "chainName": run.ChainName,
		"status": string(run.Status()), "total": run.Total, "stride": run.Stride,
		"completed": completed, "errors": errs, "unresolved": unresolved, "bypassed": bypassed,
		"createdAt": run.CreatedAt,
	}
}

func (s *APIServer) handleChainGetRun(w http.ResponseWriter, r *http.Request) {
	run := s.chainRuns.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	results := run.Results()
	offset, limit := pageParams(r, len(results))
	// Materialized, never nil: a nil slice marshals as null against a client
	// type that says array. See chain.Chain.Normalize.
	page := []chainrun.Result{}
	if offset < len(results) {
		end := min(offset+limit, len(results))
		page = results[offset:end]
	}

	body := chainRunHead(run)
	body["steps"] = run.Steps
	body["variants"] = run.Variants
	body["verdicts"] = run.Verdicts()
	body["results"] = page
	body["resultTotal"] = len(results)
	body["offset"] = offset
	body["limit"] = limit
	writeJSON(w, http.StatusOK, body)
}

func (s *APIServer) handleChainGetGrid(w http.ResponseWriter, r *http.Request) {
	run := s.chainRuns.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	writeJSON(w, http.StatusOK, chainrun.Grid(run))
}

// handleChainGetResult returns one instance including its raw bytes, fetched on
// demand rather than streamed, as the fuzzer's and sj's detail endpoints are.
func (s *APIServer) handleChainGetResult(w http.ResponseWriter, r *http.Request) {
	run := s.chainRuns.Get(r.PathValue("id"))
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
	reqRaw, respRaw := res.ReqRaw, res.RespRaw
	res.ReqRaw, res.RespRaw = nil, nil
	writeJSON(w, http.StatusOK, map[string]any{
		"result":  res,
		"reqRaw":  base64.StdEncoding.EncodeToString(reqRaw),
		"respRaw": base64.StdEncoding.EncodeToString(respRaw),
	})
}

func (s *APIServer) handleChainStopRun(w http.ResponseWriter, r *http.Request) {
	run := s.chainRuns.Get(r.PathValue("id"))
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

func (s *APIServer) handleChainDeleteRun(w http.ResponseWriter, r *http.Request) {
	run := s.chainRuns.Get(r.PathValue("id"))
	if run == nil {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	if run.Status() == chainrun.StatusRunning {
		writeError(w, http.StatusConflict, "stop the run before deleting it")
		return
	}
	s.chainRuns.Delete(run.ID)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
