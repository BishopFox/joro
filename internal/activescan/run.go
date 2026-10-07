package activescan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/event"
)

// Run is one scan execution.
type Run struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Origin    string    `json:"origin"`
	Scope     string    `json:"scope"` // "host" | "request"
	Rules     []string  `json:"rules"`
	CreatedAt time.Time `json:"createdAt"`
	Total     int       `json:"total"`

	Config Config `json:"-"`

	urls []TargetURL // the scope-filtered URLs this run exercises

	mu        sync.RWMutex
	status    Status
	completed int
	errors    int
	findings  int
	errMsgs   []string
	cancel    context.CancelFunc
}

// NewRun creates a running scan with its totals set. total is the number of work
// units the run expects to complete: one per (rule, URL).
func NewRun(id string, cfg Config, t Target, ruleIDs []string, total int) *Run {
	return &Run{
		ID:        id,
		Host:      t.Host,
		Origin:    t.Origin,
		Scope:     cfg.Scope,
		Rules:     ruleIDs,
		CreatedAt: time.Now(),
		Total:     total,
		Config:    cfg,
		urls:      t.URLs,
		status:    StatusRunning,
	}
}

// Status reports the run's state.
func (r *Run) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

// Counts reports progress.
func (r *Run) Counts() (completed, errors, findings int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.completed, r.errors, r.findings
}

// Errors returns the rule-level failures observed so far.
func (r *Run) Errors() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string{}, r.errMsgs...)
}

func (r *Run) addProgress(delta int) {
	r.mu.Lock()
	r.completed += delta
	r.mu.Unlock()
}

func (r *Run) addFinding() {
	r.mu.Lock()
	r.findings++
	r.mu.Unlock()
}

func (r *Run) addError(msg string) {
	r.mu.Lock()
	r.errors++
	r.errMsgs = append(r.errMsgs, msg)
	r.mu.Unlock()
}

func (r *Run) finish(s Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == StatusRunning {
		r.status = s
	}
}

// Stop cancels a running run.
func (r *Run) Stop() bool {
	r.mu.Lock()
	cancel := r.cancel
	running := r.status == StatusRunning
	if running {
		r.status = StatusStopped
	}
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return running
}

func (r *Run) setCancel(cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancel = cancel
}

// Deps is what a run needs from the host process.
type Deps struct {
	// Broadcast is the hub's channel, carrying event.WSEvent values.
	Broadcast chan<- any
	// Findings is the shared detect store a rule's results are filed into.
	Findings *detect.Store
	// Notify pushes the aggregate detect.summary (s.broadcastDetectSummary).
	Notify func()
	// Registry resolves the run's rule IDs to Rule implementations.
	Registry *Registry
	// RuleDeps is forwarded to each rule.
	RuleDeps RuleDeps
}

// Plan reports how many work units a scan will run and refuses one that cannot
// run, before any browser launches or byte goes on the wire.
func Plan(cfg Config, t Target, rules []Rule) (int, error) {
	if len(t.URLs) == 0 {
		return 0, fmt.Errorf("no in-scope URLs to scan")
	}
	if len(rules) == 0 {
		return 0, fmt.Errorf("no active-scan rules selected")
	}
	return len(t.URLs) * len(rules), nil
}

// Execute runs every selected rule against the target, sequentially.
func Execute(ctx context.Context, run *Run, d Deps) {
	budget := time.Duration(clampInt(run.Config.BudgetMs, DefaultBudgetMs, 1000, MaxBudgetMs)) * time.Millisecond
	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	run.setCancel(cancel)

	started := time.Now()
	broadcast(d, "activescan.started", map[string]any{
		"runId": run.ID, "host": run.Host, "origin": run.Origin,
		"scope": run.Scope, "rules": run.Rules, "total": run.Total,
	})

	rep := &reporter{run: run, d: d}
	rules := d.Registry.Resolve(run.Config.Rules)

	status := StatusComplete
	for _, rule := range rules {
		if runCtx.Err() != nil {
			status = StatusStopped
			break
		}
		if err := rule.Run(runCtx, Target{
			Scheme: schemeOf(run.Origin), Host: run.Host, Origin: run.Origin, URLs: run.urls,
		}, run.Config, d.RuleDeps, rep); err != nil {
			run.addError(fmt.Sprintf("%s: %v", rule.Name(), err))
		}
	}
	if runCtx.Err() != nil {
		status = StatusStopped
	}
	run.finish(status)

	completed, errs, findings := run.Counts()
	broadcast(d, "activescan.complete", map[string]any{
		"runId": run.ID, "status": string(run.Status()),
		"completed": completed, "errors": errs, "findings": findings,
		"durationMs": time.Since(started).Milliseconds(),
	})
}

// reporter adapts a run and its deps to the Reporter a rule writes through.
type reporter struct {
	run *Run
	d   Deps
}

func (r *reporter) Progress(delta int) {
	if delta <= 0 {
		return
	}
	r.run.addProgress(delta)
	completed, _, findings := r.run.Counts()
	broadcast(r.d, "activescan.progress", map[string]any{
		"runId": r.run.ID, "scanned": completed, "total": r.run.Total, "findings": findings,
	})
}

func (r *reporter) Finding(f detect.Finding) {
	if r.d.Findings == nil {
		return
	}
	saved, isNew := r.d.Findings.Upsert(f)
	r.run.addFinding()
	broadcast(r.d, "detect.finding", map[string]any{"finding": saved, "isNew": isNew})
	if r.d.Notify != nil {
		r.d.Notify()
	}
}

// broadcast sends blocking, from the run's own goroutine, like chainrun and
// fuzzer: Hub.Subscribe fans out without blocking, so a slow subscriber cannot
// stall the run, and blocking keeps the client's progress agreeing with the run.
func broadcast(d Deps, typ string, data map[string]any) {
	if d.Broadcast == nil {
		return
	}
	d.Broadcast <- event.WSEvent{Type: typ, Data: data}
}

func schemeOf(origin string) string {
	if len(origin) >= 8 && origin[:8] == "https://" {
		return "https"
	}
	return "http"
}
