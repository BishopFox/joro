package chainrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/chain"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/httptools"
)

// Plan refuses a run before any bytes go on the wire, and reports how many step
// instances it will send.
func Plan(cfg Config) (int, error) {
	if cfg.Chain == nil {
		return 0, fmt.Errorf("no chain")
	}
	total, err := chain.Plan(cfg.Chain, cfg.Variants)
	if err != nil {
		return 0, err
	}
	// The arming gate. A chain of GETs is a read; anything else creates orders,
	// sends mail and moves money, once per variant.
	if methods := chain.StateChangingMethods(cfg.Chain); len(methods) > 0 && !cfg.AllowStateChanging {
		return 0, fmt.Errorf("this chain sends %s requests; tick \"allow state-changing requests\" to run it",
			strings.Join(methods, ", "))
	}
	return total, nil
}

// Execute runs every variant, sequentially.
//
// Sequential end to end: the steps of a workflow are data-dependent so they
// cannot overlap, and two variants racing on the application's own state would
// produce verdicts describing the interleaving rather than the application.
func Execute(ctx context.Context, run *Run, d Deps) {
	cfg := run.Config
	delay := time.Duration(clampInt(cfg.DelayMs, DefaultDelayMs, 0, MaxDelayMs)) * time.Millisecond
	perStep := time.Duration(clampInt(cfg.TimeoutMs, DefaultTimeoutMs, 1000, MaxTimeoutMs)) * time.Millisecond
	budget := time.Duration(clampInt(cfg.BudgetMs, DefaultBudgetMs, 1000, MaxBudgetMs)) * time.Millisecond

	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	run.setCancel(cancel)

	started := time.Now()
	broadcast(d, "chain.run.started", map[string]any{
		"runId":     run.ID,
		"chainId":   run.ChainID,
		"chainName": run.ChainName,
		"variants":  len(cfg.Variants),
		"total":     run.Total,
	})

	ch := cfg.Chain
	stepIndex := make(map[string]int, len(ch.Steps))
	for i, s := range ch.Steps {
		stepIndex[s.ID] = i
	}

	status := StatusComplete
	for vi, variant := range cfg.Variants {
		if runCtx.Err() != nil {
			status = StatusStopped
			break
		}
		runVariant(runCtx, run, d, vi, variant, stepIndex, perStep, delay)
		run.setVerdict(verdictFor(run, vi, variant, stepIndex))
		emitVerdict(d, run, variant.ID)
	}

	if runCtx.Err() != nil {
		status = StatusStopped
	}
	// Any slot never reached keeps its zero Cell, which the grid reads as "not
	// run" — the same polarity apiscan.verdictFor uses for an unfilled slot, and
	// for the same reason: a cell that never ran must not read as a pass.
	run.finish(status)

	completed, errs, unresolved, bypassed := run.Counts()
	broadcast(d, "chain.run.complete", map[string]any{
		"runId":      run.ID,
		"status":     string(run.Status()),
		"completed":  completed,
		"errors":     errs,
		"unresolved": unresolved,
		"bypassed":   bypassed,
		"durationMs": time.Since(started).Milliseconds(),
	})
}

// runVariant executes one ordering and fills its row of the grid.
func runVariant(ctx context.Context, run *Run, d Deps, vi int, variant chain.Variant,
	stepIndex map[string]int, perStep, delay time.Duration) {

	ch := run.Config.Chain
	vars := chain.Vars{}
	occurrence := map[string]int{}
	ran := map[string]bool{}
	base := vi * run.Stride

	for si, stepID := range variant.Steps {
		if ctx.Err() != nil {
			return
		}
		step, idx, ok := ch.StepByID(stepID)
		if !ok {
			continue
		}
		ran[stepID] = true
		occ := occurrence[stepID]
		occurrence[stepID]++

		res := executeStep(ctx, run, d, ch, step, vars, perStep)
		res.VariantID = variant.ID
		res.StepID = stepID
		res.Label = step.Label
		res.Occurrence = occ
		classify(run, vi, idx, &res)

		// Occurrence 0 owns the grid slot; a repeat's later instances go to the
		// extras region so the grid stays rectangular and the pivot stays
		// arithmetic.
		if occ == 0 {
			res.Index = base + idx
			run.setResult(base+idx, res)
		} else {
			res.Index = run.addExtra(res)
		}
		emitResult(d, run, res)

		if delay > 0 && si+1 < len(variant.Steps) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}

	// Fill the cells for steps this variant left out.
	for idx, s := range ch.Steps {
		if ran[s.ID] {
			continue
		}
		res := Result{
			VariantID: variant.ID,
			StepID:    s.ID,
			Label:     s.Label,
			Method:    chain.MethodOf(s.ReqRaw),
			Cell:      CellSkipped,
			Index:     base + idx,
		}
		run.setResult(base+idx, res)
		emitResult(d, run, res)
	}
}

// executeStep renders, sends and captures one step instance.
func executeStep(ctx context.Context, run *Run, d Deps, ch *chain.Chain, step chain.Step,
	vars chain.Vars, perStep time.Duration) Result {

	res := Result{
		Method: chain.MethodOf(step.ReqRaw),
		URL:    step.Scheme + "://" + step.Host + chain.TargetOf(step.ReqRaw),
	}

	raw, missing, err := chain.Render(ch, step, vars)
	if err != nil {
		res.Cell = CellError
		res.Error = err.Error()
		return res
	}
	if len(missing) > 0 {
		// Do not send. A step that quietly sent a stale token would look exactly
		// like the application rejecting the request, which is the false
		// negative this whole design exists to avoid.
		res.Cell = CellUnresolved
		res.Missing = missing
		names := make([]string, 0, len(missing))
		for _, m := range missing {
			label := m.FromStep
			if s, _, ok := ch.StepByID(m.FromStep); ok {
				label = s.Label
			}
			names = append(names, fmt.Sprintf("%s (from %s)", m.Var, label))
		}
		res.Note = "needs " + strings.Join(names, ", ")
		return res
	}
	res.ReqRaw = raw

	itemCtx, cancelItem := context.WithTimeout(ctx, perStep)
	defer cancelItem()

	sent, err := httptools.SendViaProxy(itemCtx, raw, step.Scheme, step.Host, d.Send)
	if err != nil {
		res.Cell = CellError
		res.Error = annotateSendErr(err, itemCtx)
		return res
	}

	res.RespRaw = sent.RespRaw
	res.Seq = sent.Seq
	res.RequestID = sent.RequestID
	res.SeqNote = sent.SeqNote
	if sent.Method != "" {
		res.Method = sent.Method
	}
	if sent.URL != "" {
		res.URL = sent.URL
	}

	// Capture before hashing: this step's own outputs have to be in the table or
	// the value it just produced — an order id, a fresh token — is left unfolded
	// and makes the response look different from the baseline's every time.
	res.Captured = chain.Capture(ch, step, sent.RespRaw, vars)
	canonical := canonicalRaw(sent.RespRaw, vars)

	fp := httptools.FingerprintResponse(sent.Seq, canonical, sent.Duration.Milliseconds(), false)
	res.Status = fp.Status
	res.DurationMs = fp.DurationMs
	res.BodyHash = fp.BodyHash
	res.StructHash = fp.StructHash
	res.Words = fp.Words
	res.Lines = fp.Lines
	res.CanonHash = canonHash(canonical)
	// Length is reported from what actually came back, not from the canonical
	// copy: it is shown to the operator, and a folded length is a lie.
	res.Len = len(httptools.ReadResponse(sent.RespRaw).Body)
	if res.Note == "" {
		res.Note = fp.Note
	}
	return res
}

// canonHash is sha256 of the canonicalized body, first 8 hex.
// canonicalRaw decodes a response, then folds every bound value to its name.
//
// Decoding first, because the proxy leaves Content-Encoding in place: a gzip'd
// body contains no bound value as a literal, so folding it first matches nothing
// and says nothing — and every variant then reads as "changed".
//
// The encoding headers go with the body they described, so the fingerprint does
// not try to decompress plaintext.
func canonicalRaw(respRaw []byte, vars chain.Vars) []byte {
	resp := httptools.ReadResponse(respRaw)

	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d \r\n", resp.Status)
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		switch {
		case strings.EqualFold(name, "Content-Encoding"),
			strings.EqualFold(name, "Content-Length"),
			strings.EqualFold(name, "Transfer-Encoding"):
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range resp.Header.Values(name) {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	b.WriteString("\r\n")
	b.Write(chain.Canonicalize(resp.Body, vars))
	return b.Bytes()
}

func canonHash(canonical []byte) string {
	sum := sha256.Sum256(httptools.ReadResponse(canonical).Body)
	return hex.EncodeToString(sum[:4])
}

// annotateSendErr explains the failure an operator will actually hit.
//
// A timeout here is nearly always the request sitting in the operator's own
// Intercept queue, and saying so is the difference between a one-click fix and a
// hunt through the target's rate limiting. The same note resend.go carries.
func annotateSendErr(err error, ctx context.Context) string {
	if ctx.Err() == context.DeadlineExceeded {
		return err.Error() + " (if request intercept is armed, this step is waiting in the Intercept queue)"
	}
	return err.Error()
}

func emitResult(d Deps, run *Run, res Result) {
	res.ReqRaw, res.RespRaw = nil, nil
	broadcast(d, "chain.run.result", map[string]any{
		"runId": run.ID, "result": res,
	})
}

func emitVerdict(d Deps, run *Run, variantID string) {
	for _, v := range run.Verdicts() {
		if v.VariantID == variantID {
			broadcast(d, "chain.run.variant", map[string]any{"runId": run.ID, "verdict": v})
			return
		}
	}
}

// broadcast sends blocking, from the run's own goroutine, like fuzzer.result and
// spec.run.result: Hub.Subscribe fans out to in-process consumers without
// blocking, so a slow subscriber cannot stall the run, and blocking here is what
// keeps the client's row count agreeing with the run's total.
func broadcast(d Deps, typ string, data map[string]any) {
	if d.Broadcast == nil {
		return
	}
	d.Broadcast <- event.WSEvent{Type: typ, Data: data}
}
