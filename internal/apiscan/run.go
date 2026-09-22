package apiscan

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/apispec"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/httptools"
)

// Plan reports how many requests a config will send, and refuses one that is
// too large before any of it goes on the wire.
func Plan(cfg Config) (int, error) {
	if len(cfg.Ops) == 0 {
		return 0, fmt.Errorf("no operations selected")
	}
	if len(cfg.Profiles) == 0 {
		return 0, fmt.Errorf("no auth profiles selected; use a single empty profile for an unauthenticated scan")
	}
	if len(cfg.Profiles) > MaxProfiles {
		return 0, fmt.Errorf("%d profiles exceeds the limit of %d", len(cfg.Profiles), MaxProfiles)
	}
	total := len(cfg.Ops) * len(cfg.Profiles)
	if total > MaxRequestsPerRun {
		return 0, fmt.Errorf(
			"%d operations x %d profiles is %d requests, over the %d-request limit; "+
				"select fewer operations, or drive Joro's fuzzer from the Fuzz tab for a run that size",
			len(cfg.Ops), len(cfg.Profiles), total, MaxRequestsPerRun)
	}
	return total, nil
}

// Execute runs a scan or a matrix.
//
// The shape mirrors httptools.Batch: one shared ticker as the rate limiter, a
// channel of indices, N workers, one claim set for the whole run, and results
// written into pre-sized slots by index rather than appended. Batch's own doc
// comment records that duplicating this shape is the repo's answer to the
// fuzzer's runner not being extractable, and the same reasoning applies here.
func Execute(ctx context.Context, run *Run, d Deps) {
	cfg := run.Config

	conc := clampInt(cfg.Concurrency, DefaultConcurrency, 1, MaxConcurrency)
	perItem := time.Duration(clampInt(cfg.TimeoutMs, DefaultTimeoutMs, 1000, MaxTimeoutMs)) * time.Millisecond
	budget := time.Duration(clampInt(cfg.BudgetMs, DefaultBudgetMs, 1000, MaxBudgetMs)) * time.Millisecond

	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	run.setCancel(cancel)

	var limiter <-chan time.Time
	if cfg.RatePerSec > 0 {
		rate := min(cfg.RatePerSec, MaxRatePerSec)
		tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
		defer tick.Stop()
		limiter = tick.C
	}

	// One claim set for the run, so two workers finishing at once cannot
	// correlate their sends to the same History row. In a matrix this is not an
	// edge case: two profiles hitting one operation often produce byte-identical
	// responses, which is exactly when correlate falls through to claim order.
	sendDeps := d.Send
	sendDeps.Claims = httptools.NewClaimSet()

	methods := cfg.Methods
	if len(methods) == 0 {
		methods = apispec.DefaultMethods()
	}

	start := time.Now()
	broadcast(d, "spec.run.started", map[string]any{
		"runId": run.ID, "kind": string(run.Kind), "total": run.Total,
		"profiles": profileSummaries(cfg.Profiles),
	})

	total := len(cfg.Ops) * len(cfg.Profiles)
	work := make(chan int, conc)
	var wg sync.WaitGroup

	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				opIdx := idx / len(cfg.Profiles)
				profIdx := idx % len(cfg.Profiles)
				op := &cfg.Ops[opIdx]
				profile := cfg.Profiles[profIdx]

				res := Result{
					OpID: op.ID, ProfileID: profile.ID,
					Method: op.Method, Path: op.Path,
				}

				// The safety gate. A skipped item still fills its slot, so the
				// client can correlate every row back to what it asked for and can
				// see why one was not sent.
				if !slices.Contains(methods, strings.ToUpper(op.Method)) {
					res.Skipped = "method"
					res.Triage = TriageWarn
					run.setResult(idx, &res)
					emitResult(d, run, res)
					continue
				}
				if op.Destructive && !cfg.AllowDestructive {
					res.Skipped = "destructive"
					res.Note = strings.Join(op.DestructiveReasons, ", ")
					res.Triage = TriageWarn
					run.setResult(idx, &res)
					emitResult(d, run, res)
					continue
				}

				if limiter != nil {
					select {
					case <-runCtx.Done():
						res.Skipped = "budget"
						res.Triage = TriageWarn
						run.setResult(idx, &res)
						emitResult(d, run, res)
						continue
					case <-limiter:
					}
				}
				if runCtx.Err() != nil {
					res.Skipped = "budget"
					res.Triage = TriageWarn
					run.setResult(idx, &res)
					emitResult(d, run, res)
					continue
				}

				raw, target, err := apispec.Render(op, cfg.Server, cfg.Values[op.ID], profile.Auth,
					apispec.RenderOptions{UserAgent: cfg.UserAgent})
				if err != nil {
					res.Skipped = "render"
					res.Error = err.Error()
					res.Triage = TriageWarn
					run.setResult(idx, &res)
					emitResult(d, run, res)
					continue
				}
				res.URL = target.Scheme + "://" + target.Host + target.Path
				res.ReqPath = target.Path
				res.ReqRaw = raw

				itemCtx, itemCancel := context.WithTimeout(runCtx, perItem)
				sent, err := httptools.SendViaProxy(itemCtx, raw, target.Scheme, target.Host, sendDeps)
				itemCancel()
				if err != nil {
					res.Error = shortErr(err)
					res.Triage = TriageWarn
					run.setResult(idx, &res)
					emitResult(d, run, res)
					continue
				}

				applyFingerprint(&res, sent)
				run.setResult(idx, &res)
				emitResult(d, run, res)
			}
		}()
	}

	for i := range total {
		select {
		case work <- i:
		case <-runCtx.Done():
			// Fill the rest so the client is not left waiting on rows that will
			// never arrive.
			for j := i; j < total; j++ {
				op := &cfg.Ops[j/len(cfg.Profiles)]
				res := Result{
					Skipped: "budget", Triage: TriageWarn,
					OpID: op.ID, Method: op.Method, Path: op.Path,
					ProfileID: cfg.Profiles[j%len(cfg.Profiles)].ID,
				}
				run.setResult(j, &res)
				emitResult(d, run, res)
			}
			close(work)
			wg.Wait()
			finishRun(d, run, start)
			return
		}
	}
	close(work)
	wg.Wait()
	finishRun(d, run, start)
}

// applyFingerprint copies a send's outcome onto a result.
//
// FingerprintResponse rather than status and length: StructHash folds out CSRF
// tokens, timestamps, UUIDs and nonces, which is what stops an auth matrix
// flagging every row where two renderings of one page differ only in a nonce.
func applyFingerprint(res *Result, sent *httptools.ProxySendResult) {
	fp := httptools.FingerprintResponse(sent.Seq, sent.RespRaw, sent.Duration.Milliseconds(), false)
	res.Seq = sent.Seq
	res.RequestID = sent.RequestID
	res.SeqNote = sent.SeqNote
	res.Status = fp.Status
	res.Len = fp.Len
	res.DurationMs = fp.DurationMs
	res.BodyHash = fp.BodyHash
	res.StructHash = fp.StructHash
	res.Words = fp.Words
	res.Lines = fp.Lines
	res.Note = fp.Note
	res.ContentType = fp.CT
	res.RespRaw = sent.RespRaw
	res.Triage = TriageOf(fp.Status, "")
}

func finishRun(d Deps, run *Run, start time.Time) {
	status := StatusComplete
	if run.Status() == StatusStopped {
		status = StatusStopped
	}
	run.finish(status)
	completed, errs, skipped, hits := run.Counts()
	broadcast(d, "spec.run.complete", map[string]any{
		"runId": run.ID, "kind": string(run.Kind), "status": string(run.Status()),
		"completed": completed, "errors": errs, "skipped": skipped, "hits": hits,
		"durationMs": time.Since(start).Milliseconds(),
	})
}

// emitResult sends one row.
//
// Blocking, from the run's own goroutine, like fuzzer.result: Hub.Subscribe fans
// out to in-process consumers without blocking, so a slow subscriber cannot
// stall the run, and sending blocking here is what keeps the client's row count
// agreeing with the run's total.
func emitResult(d Deps, run *Run, res Result) {
	res.ReqRaw, res.RespRaw = nil, nil
	broadcast(d, "spec.run.result", map[string]any{
		"runId": run.ID, "kind": string(run.Kind), "result": res,
	})
}

func broadcast(d Deps, typ string, data map[string]any) {
	if d.Broadcast == nil {
		return
	}
	d.Broadcast <- event.WSEvent{Type: typ, Data: data}
}

func profileSummaries(profiles []Profile) []map[string]any {
	out := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, map[string]any{"id": p.ID, "label": p.Label, "rank": p.Rank})
	}
	return out
}

func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg)-i < 60 {
		return msg[i+2:]
	}
	if len(msg) > 120 {
		return msg[:120]
	}
	return msg
}
