package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/chain"
	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/proxy"
)

// maxRecordCandidates bounds what a record window hands back for trimming. A
// recording left running over a browsing session would otherwise return the whole
// capture ring.
const maxRecordCandidates = 500

func (s *APIServer) handleChainListChains(w http.ResponseWriter, r *http.Request) {
	chains := s.chainStore.List()
	out := make([]map[string]any, 0, len(chains))
	for _, c := range chains {
		out = append(out, chainSummaryBody(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"chains": out})
}

// chainSummaryBody is the list projection: enough to render the picker without
// shipping every step's raw bytes, which are megabytes across a project.
func chainSummaryBody(c *chain.Chain) map[string]any {
	hosts := map[string]bool{}
	for _, st := range c.Steps {
		hosts[st.Host] = true
	}
	list := make([]string, 0, len(hosts))
	for h := range hosts {
		list = append(list, h)
	}
	sort.Strings(list)
	return map[string]any{
		"id": c.ID, "name": c.Name,
		"steps": len(c.Steps), "bindings": len(c.Bindings),
		"hosts": list, "createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

func (s *APIServer) handleChainGetChain(w http.ResponseWriter, r *http.Request) {
	c := s.chainStore.Get(r.PathValue("id"))
	if c == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	writeJSON(w, http.StatusOK, chainBody(c))
}

// chainBody renders a chain with its raws base64-encoded. Raw bytes are not
// JSON-safe and a captured request routinely is not UTF-8.
func chainBody(c *chain.Chain) map[string]any {
	steps := make([]map[string]any, 0, len(c.Steps))
	for _, st := range c.Steps {
		steps = append(steps, map[string]any{
			"id": st.ID, "label": st.Label, "scheme": st.Scheme, "host": st.Host,
			"reqRaw":    base64.StdEncoding.EncodeToString(st.ReqRaw),
			"respRaw":   base64.StdEncoding.EncodeToString(st.RespRaw),
			"originSeq": st.OriginSeq, "setup": st.Setup, "edits": st.Edits,
			"method": chain.MethodOf(st.ReqRaw),
		})
	}
	return map[string]any{
		"id": c.ID, "name": c.Name, "goalStepId": c.GoalStepID,
		"steps": steps, "bindings": c.Bindings,
		"createdAt": c.CreatedAt, "updatedAt": c.UpdatedAt,
	}
}

// chainInput is the write shape. Raws arrive base64 for the same reason they
// leave that way.
type chainInput struct {
	Name       string `json:"name"`
	GoalStepID string `json:"goalStepId"`
	Steps      []struct {
		ID        string           `json:"id"`
		Label     string           `json:"label"`
		Scheme    string           `json:"scheme"`
		Host      string           `json:"host"`
		ReqRaw    string           `json:"reqRaw"`
		RespRaw   string           `json:"respRaw"`
		OriginSeq int              `json:"originSeq"`
		Setup     bool             `json:"setup"`
		Edits     []httptools.Edit `json:"edits"`
	} `json:"steps"`
	Bindings []chain.Binding `json:"bindings"`
}

func (in chainInput) toChain() (*chain.Chain, error) {
	c := &chain.Chain{Name: in.Name, GoalStepID: in.GoalStepID, Bindings: in.Bindings}
	for i, st := range in.Steps {
		req, err := base64.StdEncoding.DecodeString(st.ReqRaw)
		if err != nil {
			return nil, fmt.Errorf("step %d: request is not valid base64", i+1)
		}
		resp, err := base64.StdEncoding.DecodeString(st.RespRaw)
		if err != nil {
			return nil, fmt.Errorf("step %d: response is not valid base64", i+1)
		}
		step := chain.Step{
			ID: st.ID, Label: st.Label, Scheme: st.Scheme, Host: st.Host,
			ReqRaw: req, RespRaw: resp, OriginSeq: st.OriginSeq, Setup: st.Setup,
			Edits: st.Edits,
		}
		if step.Label == "" {
			step.Label = chain.Label(req)
		}
		c.Steps = append(c.Steps, step)
	}
	return c, nil
}

func (s *APIServer) handleChainCreateChain(w http.ResponseWriter, r *http.Request) {
	var in chainInput
	if err := decodeJSONLimit(r, &in, maxBulkJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	c, err := in.toChain()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	chain.Reindex(c)
	saved, err := s.chainStore.Create(c)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, chainBody(saved))
}

func (s *APIServer) handleChainUpdateChain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.chainStore.Get(id) == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	var in chainInput
	if err := decodeJSONLimit(r, &in, maxBulkJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	c, err := in.toChain()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := s.chainStore.Update(id, c)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, chainBody(saved))
}

func (s *APIServer) handleChainDeleteChain(w http.ResponseWriter, r *http.Request) {
	// A run holds a snapshot of the chain, so deleting one does not disturb a run
	// in flight and there is nothing to refuse here.
	if !s.chainStore.Delete(r.PathValue("id")) {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// chainFromHistoryRequest builds a chain out of selected History rows, or
// appends them to one that already exists.
type chainFromHistoryRequest struct {
	Name string `json:"name"`
	Seqs []int  `json:"seqs"`

	// ChainID appends to an existing chain instead of creating one. History has
	// one selected row at a time, so a chain is built a step at a time; appending
	// server-side is what lets correlation re-run over the extended chain and
	// wire the new step to values the earlier ones already produce.
	ChainID string `json:"chainId,omitempty"`
}

// handleChainFromHistory is the primary way a chain comes into existence.
//
// Rows are addressed by Seq rather than by id: it is the handle the capture store
// is indexed on, and the only one a client can hold across a page reload without
// carrying raw bytes through history.pushState.
func (s *APIServer) handleChainFromHistory(w http.ResponseWriter, r *http.Request) {
	var req chainFromHistoryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(req.Seqs) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one request")
		return
	}
	if len(req.Seqs) > chain.MaxSteps {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("%d requests exceeds the limit of %d steps", len(req.Seqs), chain.MaxSteps))
		return
	}

	// Ascending, because a chain is an ordering and the order the rows were
	// clicked in is not it.
	seqs := append([]int(nil), req.Seqs...)
	sort.Ints(seqs)

	// A non-positive seq is a malformed request, not an evicted one, and the two
	// need different words. Reporting a client that sent 0 or null as "no longer
	// in the capture buffer" sends whoever is debugging it to look at eviction,
	// which is exactly the wrong place — and is how a client sending undefined
	// went unnoticed.
	for _, seq := range seqs {
		if seq <= 0 {
			writeError(w, http.StatusBadRequest,
				"no valid request sequence numbers were supplied")
			return
		}
	}

	steps := make([]chain.Step, 0, len(seqs))
	var missing []int
	for _, seq := range seqs {
		item := s.store.GetBySeq(seq)
		if item == nil {
			missing = append(missing, seq)
			continue
		}
		steps = append(steps, chainStepFromCapture(item))
	}
	if len(steps) == 0 {
		writeError(w, http.StatusBadRequest, "none of those requests are still in the capture buffer")
		return
	}

	var saved *chain.Chain
	var err error

	if req.ChainID != "" {
		existing := s.chainStore.Get(req.ChainID)
		if existing == nil {
			writeError(w, http.StatusNotFound, "no such chain")
			return
		}
		existing.Steps = append(existing.Steps, steps...)
		if len(existing.Steps) > chain.MaxSteps {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("that would make %d steps, over the limit of %d", len(existing.Steps), chain.MaxSteps))
			return
		}
		// Reindex before correlating: correlation records byte spans against step
		// ids, so it has to run after the ids are final.
		chain.Reindex(existing)
		for i := range existing.Steps {
			if existing.Steps[i].Label == "" {
				existing.Steps[i].Label = chain.Label(existing.Steps[i].ReqRaw)
			}
		}
		existing.Bindings = mergeBindings(existing.Bindings, chain.Correlate(existing))
		saved, err = s.chainStore.Update(existing.ID, existing)
	} else {
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "chain"
		}
		c := chain.New(name, steps)

		// Correlate on the way in. A chain that arrives already wired is the
		// difference between a usable artifact and a list of requests the
		// operator has to hand-thread a CSRF token through.
		c.Bindings = chain.Correlate(c)
		saved, err = s.chainStore.Create(c)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := chainBody(saved)
	if len(missing) > 0 {
		resp["warning"] = fmt.Sprintf("%d selected requests were no longer in the capture buffer", len(missing))
	}
	writeJSON(w, http.StatusCreated, resp)
}

func chainStepFromCapture(item *proxy.CapturedRequest) chain.Step {
	scheme := "https"
	if strings.HasPrefix(strings.ToLower(item.URL), "http://") {
		scheme = "http"
	}
	return chain.Step{
		Scheme:    scheme,
		Host:      item.Host,
		ReqRaw:    append([]byte(nil), item.ReqRaw...),
		RespRaw:   append([]byte(nil), item.RespRaw...),
		OriginSeq: item.Seq,
	}
}

// handleChainRecordStart returns the capture watermark to record from.
//
// Recording reads the store forward from a cursor rather than hooking the proxy,
// which is the arrangement internal/detect's scanner already documents: no second
// path through the capture hot loop, and nothing to unwind if the operator
// navigates away without stopping.
func (s *APIServer) handleChainRecordStart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"cursor": s.store.LastSeq()})
}

type chainRecordStopRequest struct {
	Cursor    int    `json:"cursor"`
	Host      string `json:"host,omitempty"`
	ScopeOnly bool   `json:"scopeOnly,omitempty"`
}

// handleChainRecordStop returns the candidate rows captured since the cursor, for
// the operator to trim into steps. It creates nothing: a recording is a selection
// aid, and a chain built from unreviewed traffic is mostly analytics beacons.
func (s *APIServer) handleChainRecordStop(w http.ResponseWriter, r *http.Request) {
	var req chainRecordStopRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	items := s.store.SinceSeq(req.Cursor, maxRecordCandidates)
	host := strings.ToLower(strings.TrimSpace(req.Host))

	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if host != "" && !strings.Contains(strings.ToLower(it.Host), host) {
			continue
		}
		if req.ScopeOnly && !s.scope.HostInScope(it.Host) {
			continue
		}
		out = append(out, map[string]any{
			"seq": it.Seq, "method": it.Method, "url": it.URL, "host": it.Host,
			"status": it.StatusCode, "contentType": it.ContentType,
			"size": it.ResponseSize, "timestamp": it.Timestamp,
			"label": chain.Label(it.ReqRaw),
		})
	}
	// Ascending: SinceSeq walks backwards from newest, and a recording reads
	// forwards.
	sort.Slice(out, func(i, j int) bool { return out[i]["seq"].(int) < out[j]["seq"].(int) })
	writeJSON(w, http.StatusOK, map[string]any{"candidates": out, "cursor": s.store.LastSeq()})
}

// handleChainCorrelate proposes bindings and persists nothing.
//
// A proposal, like a render is a preview: correlation is a heuristic over
// entropy and literal occurrence, and writing its guesses straight into the chain
// would put the operator in the position of un-picking them.
func (s *APIServer) handleChainCorrelate(w http.ResponseWriter, r *http.Request) {
	c := s.chainStore.Get(r.PathValue("id"))
	if c == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	// Re-keyed before they leave: the client appends accepted proposals straight
	// into the open chain.
	proposed := assignBindingIDs(c.Bindings, chain.Correlate(c))

	// Report which proposals are new, so the UI can offer them without
	// discarding bindings the operator has already accepted or hand-written.
	existing := map[string]bool{}
	for _, b := range c.Bindings {
		existing[bindingKey(b)] = true
	}
	out := make([]map[string]any, 0, len(proposed))
	for _, b := range proposed {
		out = append(out, map[string]any{"binding": b, "isNew": !existing[bindingKey(b)]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposed": out})
}

// mergeBindings keeps every existing binding and adds only proposals that are
// not already present.
//
// Additive rather than replacing, because a re-correlation must not discard a
// binding the operator hand-wrote, renamed, or set to send its recorded value.
func mergeBindings(existing, proposed []chain.Binding) []chain.Binding {
	have := make(map[string]bool, len(existing))
	for _, b := range existing {
		have[bindingKey(b)] = true
	}
	fresh := make([]chain.Binding, 0, len(proposed))
	for _, b := range proposed {
		if have[bindingKey(b)] {
			continue
		}
		fresh = append(fresh, b)
		have[bindingKey(b)] = true
	}
	return append(append([]chain.Binding(nil), existing...), assignBindingIDs(existing, fresh)...)
}

// assignBindingIDs re-keys proposals against the ids a chain already holds.
//
// Correlate numbers from one every run, and a count of the existing bindings is
// not the next free id once one has been deleted — so the collision surfaces as
// a refused save, several clicks from the accept that caused it.
func assignBindingIDs(existing, proposed []chain.Binding) []chain.Binding {
	taken := make(map[string]bool, len(existing))
	for _, b := range existing {
		taken[b.ID] = true
	}
	next := 1
	out := make([]chain.Binding, 0, len(proposed))
	for _, b := range proposed {
		for {
			id := "b" + strconv.Itoa(next)
			next++
			if !taken[id] {
				b.ID = id
				taken[id] = true
				break
			}
		}
		out = append(out, b)
	}
	return out
}

// bindingKey identifies a binding by what it does rather than by its id, so a
// re-run of correlation recognizes a proposal the operator already accepted.
func bindingKey(b chain.Binding) string {
	var sb strings.Builder
	sb.WriteString(b.FromStep)
	sb.WriteString(">")
	sb.WriteString(b.ToStep)
	sb.WriteString(">")
	sb.WriteString(b.Source.Kind)
	sb.WriteString(":")
	sb.WriteString(b.Source.Name)
	sb.WriteString(b.Source.Path)
	for _, sp := range b.Spans {
		fmt.Fprintf(&sb, "@%d-%d", sp.Start, sp.End)
	}
	return sb.String()
}

// chainPreviewRequest renders a variant without sending it.
type chainPreviewRequest struct {
	VariantID string   `json:"variantId"`
	Kinds     []string `json:"kinds,omitempty"`
}

// handleChainPreview renders every step of one variant and never sends.
//
// The cheap way to confirm substitution is right before arming a sweep that
// creates real orders. Values a previous step would have produced are unknown
// here, so a step that consumes one renders as unresolved — which is exactly what
// the run would do, and is the point: the preview shows where an ordering breaks
// before it costs anything.
func (s *APIServer) handleChainPreview(w http.ResponseWriter, r *http.Request) {
	c := s.chainStore.Get(r.PathValue("id"))
	if c == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	var req chainPreviewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	variants := chain.GenerateVariants(c, req.Kinds)
	var chosen *chain.Variant
	for i := range variants {
		if variants[i].ID == req.VariantID || req.VariantID == "" {
			chosen = &variants[i]
			break
		}
	}
	if chosen == nil {
		writeError(w, http.StatusNotFound, "no such variant")
		return
	}

	// Seed the table with each binding's recorded value so the preview shows the
	// substitution actually happening. A run resolves these from live responses;
	// here there are none, and rendering every step unresolved would show the
	// operator nothing about whether the spans are right.
	vars := chain.Vars{}
	for _, b := range c.Bindings {
		vars[b.Var] = b.Recorded
	}

	steps := make([]map[string]any, 0, len(chosen.Steps))
	for _, id := range chosen.Steps {
		st, _, ok := c.StepByID(id)
		if !ok {
			continue
		}
		raw, missing, err := chain.Render(c, st, vars)
		entry := map[string]any{"stepId": id, "label": st.Label}
		switch {
		case err != nil:
			entry["error"] = err.Error()
		case len(missing) > 0:
			entry["missing"] = missing
		default:
			entry["raw"] = base64.StdEncoding.EncodeToString(raw)
		}
		steps = append(steps, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"variant": chosen, "steps": steps})
}

// chainBindPreviewRequest is one operator-chosen value offered for binding.
//
// The value, not an offset: the pane shows the decoded response, whose offsets
// mean nothing against the recorded bytes. Base64 because a run of bytes out of
// a response is not reliably UTF-8.
type chainBindPreviewRequest struct {
	FromStep   string                  `json:"fromStep"`
	Value      string                  `json:"value"`
	Occurrence int                     `json:"occurrence,omitempty"`
	Source     *chain.Source           `json:"source,omitempty"`
	ToSteps    []string                `json:"toSteps,omitempty"`
	Spans      map[string][]chain.Span `json:"spans,omitempty"`
}

// handleChainBindPreview proposes bindings for one value and persists nothing.
//
// A proposal, like correlation: nothing here is confirmed against a live
// response. It reuses correlation's envelope so the client has one accept path.
func (s *APIServer) handleChainBindPreview(w http.ResponseWriter, r *http.Request) {
	c := s.chainStore.Get(r.PathValue("id"))
	if c == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	var req chainBindPreviewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "value is not base64")
		return
	}

	p, err := chain.ProposeBinding(c, req.FromStep, string(value), chain.BindOptions{
		Occurrence: req.Occurrence,
		Source:     req.Source,
		ToSteps:    req.ToSteps,
		Spans:      req.Spans,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	fresh := make([]chain.Binding, 0, len(p.Targets))
	for _, t := range p.Targets {
		fresh = append(fresh, t.Binding)
	}
	keyed := assignBindingIDs(c.Bindings, fresh)

	existing := map[string]bool{}
	for _, b := range c.Bindings {
		existing[bindingKey(b)] = true
	}
	out := make([]map[string]any, 0, len(keyed))
	for i, b := range keyed {
		out = append(out, map[string]any{
			"binding":  b,
			"isNew":    !existing[bindingKey(b)],
			"conflict": p.Targets[i].Conflict,
			"note":     p.Targets[i].Note,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"var":      p.Var,
		"recorded": base64.StdEncoding.EncodeToString([]byte(p.Recorded)),
		"sources":  p.Sources,
		"proposed": out,
		"warnings": p.Warnings,
	})
}

// handleChainStepResponse returns a step's recorded response, decoded.
//
// Decoded here, not in the client: ReadResponse is also what the sources this
// pane produces are evaluated against, so a TypeScript decoder would be a second
// answer to what the step returned. On demand, because chainBody already ships
// every step's raws and a decoded copy would double every chain GET.
func (s *APIServer) handleChainStepResponse(w http.ResponseWriter, r *http.Request) {
	c := s.chainStore.Get(r.PathValue("id"))
	if c == nil {
		writeError(w, http.StatusNotFound, "no such chain")
		return
	}
	st, _, ok := c.StepByID(r.PathValue("stepId"))
	if !ok {
		writeError(w, http.StatusNotFound, "no such step")
		return
	}
	resp := httptools.ReadResponse(st.RespRaw)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  resp.Status,
		"headers": base64.StdEncoding.EncodeToString(chainHeaderBytes(resp)),
		"body":    base64.StdEncoding.EncodeToString(resp.Body),
		// Verbatim from the parser, so a body this could not decode says which
		// encoding defeated it rather than rendering as broken text.
		"decoded": resp.Decoded,
		"bodyLen": len(resp.Body),
	})
}

// chainHeaderBytes re-serializes a parsed response's status line and headers.
// A regex or between source resolves against headers too, so they have to be
// selectable in the pane.
func chainHeaderBytes(resp httptools.Response) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d\r\n", resp.Status)
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range resp.Header.Values(name) {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	return []byte(b.String())
}
