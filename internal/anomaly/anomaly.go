// Package anomaly finds endpoints that don't look like anything else on their
// host — the lone JSON handler in an HTML app, a single 200 among 403s, an
// unusually large or slow response, a rare extension or parameter, an endpoint
// exposing a framework header the rest of the host does not. It is a triage aid
// that points attention at what to pursue, not a vulnerability claim.
//
// It is a separate package from internal/detect on purpose. The detect engine's
// three load-bearing properties — it judges one message at a time, its analyzers
// hold no state, and its Upsert keying makes rescans byte-for-byte idempotent —
// are exactly what an outlier question cannot honor. "Is this endpoint unlike
// its siblings?" is answered against a per-host baseline: shared, mutable state
// whose verdict depends on how much traffic has been seen. Computing it inside
// the detect engine would break the fan-out and the idempotent rescan both.
//
// So the computation lives here and only the *results* land in detect: this
// package mints detect.Findings under CategoryAnomaly through detect.FindingID
// and detect.Store.Upsert — the same path internal/capreg uses for agent-reported
// findings — which gives the anomaly findings the Detect table, triage,
// project persistence, the dashboard widget, triggers and webhooks for free.
//
// The engine runs on its own interval (not the proxy request path), maintains an
// incremental per-capture record cache keyed by sequence number, rebuilds
// baselines each cycle, upserts the current outliers, and retracts findings that
// are no longer outliers — but never a finding the operator has triaged (marked
// a false positive or noted), mirroring how detect's own purge preserves those.
package anomaly

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

// cycleInterval is how often baselines are rebuilt. Longer than detect's live
// tick because this is a whole-host recompute, not a per-capture scan.
const cycleInterval = 20 * time.Second

// batchSize bounds one SinceSeq pull during intake.
const batchSize = 500

// Engine owns the record cache and the set of anomaly findings it manages.
type Engine struct {
	store     *proxy.Store
	scope     *proxy.Scope
	findings  *detect.Store
	config    func() detect.Config
	broadcast chan<- any
	notify    func() // called after a cycle changes the store, to push detect.summary

	mu      sync.Mutex
	records map[int]*record
	cursor  int
	// managed maps a finding ID this engine owns to the signature (severity +
	// evidence) last emitted for it, so a cycle re-emits only what changed and
	// knows exactly which findings to reconcile.
	managed map[string]string
}

// NewEngine constructs the engine. config is read every cycle so a live toggle
// or sensitivity change takes effect without a restart; notify pushes the
// aggregate detect.summary (it needs the detect engine's rule-enabled predicate,
// which lives in the API layer).
func NewEngine(store *proxy.Store, scope *proxy.Scope, findings *detect.Store, config func() detect.Config, broadcast chan<- any, notify func()) *Engine {
	return &Engine{
		store:     store,
		scope:     scope,
		findings:  findings,
		config:    config,
		broadcast: broadcast,
		notify:    notify,
		records:   map[int]*record{},
		managed:   map[string]string{},
	}
}

// Run rebuilds baselines on an interval until ctx is cancelled, mirroring the
// detect scanner's loop.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(cycleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.RunCycle()
		}
	}
}

// ResetCursor is called wherever proxy.Store rewrites its sequence numbering
// (Clear zeroes it, a project load rewrites it), the same obligation the detect
// scanner's cursor has. It drops the record cache: a rewrite invalidates the
// seq keys the cache is built on.
func (e *Engine) ResetCursor(seq int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cursor = seq
	e.records = map[int]*record{}
}

// RunCycle performs one intake-and-analyze pass. Exported so a test or a manual
// trigger can drive it without the ticker.
func (e *Engine) RunCycle() {
	cfg := e.config()
	if !cfg.AnomalyEnabled {
		e.retractAll()
		return
	}
	e.intake()
	e.analyze(cfg)
}

// intake fingerprints captures newer than the cursor into the record cache and
// drops records whose sequence numbers have been evicted from the store.
func (e *Engine) intake() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.store.Count() == 0 {
		e.records = map[int]*record{}
		return
	}
	if oldest := e.store.SinceSeq(0, 1); len(oldest) == 1 {
		minSeq := oldest[0].Seq
		for seq := range e.records {
			if seq < minSeq {
				delete(e.records, seq)
			}
		}
	}
	for {
		batch := e.store.SinceSeq(e.cursor, batchSize)
		if len(batch) == 0 {
			break
		}
		for _, cr := range batch {
			if cr.Seq > e.cursor {
				e.cursor = cr.Seq
			}
			if r := buildRecord(cr); r != nil {
				e.records[r.seq] = r
			}
		}
		if len(batch) < batchSize {
			break
		}
	}
}

// analyze groups the cached records by host, runs the signals, and commits.
func (e *Engine) analyze(cfg detect.Config) {
	e.mu.Lock()
	recs := make([]*record, 0, len(e.records))
	for _, r := range e.records {
		recs = append(recs, r)
	}
	prev := e.managed
	e.mu.Unlock()

	th := thresholdsFor(cfg.AnomalySensitivity)
	byHost := map[string][]*record{}
	for _, r := range recs {
		if cfg.ScopeOnly && !e.scope.InScope(r.host, r.method, r.rawPath) {
			continue
		}
		if hostExcluded(r.host, cfg.ExcludeHosts) {
			continue
		}
		byHost[r.host] = append(byHost[r.host], r)
	}

	var cands []detect.Finding
	for host, hr := range byHost {
		cands = append(cands, analyzeHost(host, hr, th)...)
	}
	e.commit(cands, prev)
}

// commit upserts the current outliers, emits what is new or changed, and retracts
// managed findings no longer present unless the operator has triaged them.
func (e *Engine) commit(cands []detect.Finding, prev map[string]string) {
	next := make(map[string]string, len(cands))
	changed := false
	for _, f := range cands {
		sig := string(f.Severity) + "|" + f.Evidence
		next[f.ID] = sig
		// Unchanged since last cycle: leave the store untouched. Every Upsert
		// bumps the findings-store revision, which detectSignature folds into the
		// autosave fingerprint, so re-writing a steady finding each cycle would
		// force a project save every 20s for no reason.
		if prev[f.ID] == sig {
			continue
		}
		stored, isNew := e.findings.Upsert(f)
		if isNew {
			changed = true
		}
		e.emit(*stored, isNew)
	}
	for id := range prev {
		if _, still := next[id]; still {
			continue
		}
		f, ok := e.findings.Get(id)
		if !ok {
			continue
		}
		if f.FalsePositive || strings.TrimSpace(f.Notes) != "" {
			continue // keep triaged findings; stop managing them
		}
		if e.findings.Delete(id) {
			changed = true
		}
	}

	e.mu.Lock()
	e.managed = next
	e.mu.Unlock()

	if changed && e.notify != nil {
		e.notify()
	}
}

// retractAll drops every managed finding (except triaged ones) when the feature
// is turned off. The record cache is kept so a re-enable is cheap.
func (e *Engine) retractAll() {
	e.mu.Lock()
	prev := e.managed
	e.managed = map[string]string{}
	e.mu.Unlock()
	if len(prev) == 0 {
		return
	}
	changed := false
	for id := range prev {
		f, ok := e.findings.Get(id)
		if !ok {
			continue
		}
		if f.FalsePositive || strings.TrimSpace(f.Notes) != "" {
			continue
		}
		if e.findings.Delete(id) {
			changed = true
		}
	}
	if changed && e.notify != nil {
		e.notify()
	}
}

func (e *Engine) emit(f detect.Finding, isNew bool) {
	if e.broadcast == nil {
		return
	}
	select {
	case e.broadcast <- event.WSEvent{
		Type: "detect.finding",
		Data: map[string]any{"finding": f, "isNew": isNew},
	}:
	default:
	}
}

// hostExcluded mirrors the detect engine's substring host exclusion.
func hostExcluded(host string, exclude []string) bool {
	for _, ex := range exclude {
		if ex != "" && strings.Contains(host, ex) {
			return true
		}
	}
	return false
}
