package detect

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

const (
	// scanInterval is how often the cursor loop looks for new captures. An idle
	// tick costs one mutex acquire and one int read.
	scanInterval = 250 * time.Millisecond
	// maxPerTick bounds work per tick; a burst drains over several ticks.
	maxPerTick = 200
	// progressInterval throttles rescan progress events.
	progressInterval = 500 * time.Millisecond
)

// ScanStatus reports rescan progress.
type ScanStatus struct {
	Running     bool      `json:"running"`
	JobID       string    `json:"jobId,omitempty"`
	Kind        string    `json:"kind,omitempty"`
	Scanned     int       `json:"scanned"`
	Total       int       `json:"total"`
	FindingsNew int       `json:"findingsNew"`
	StartedAt   time.Time `json:"startedAt,omitempty"`
	FinishedAt  time.Time `json:"finishedAt,omitempty"`
	Status      string    `json:"status,omitempty"` // "running" | "complete" | "stopped"
}

// RescanRequest describes an on-demand scan.
type RescanRequest struct {
	// Scope is "all" (every captured request) or "host".
	Scope string `json:"scope"`
	Host  string `json:"host,omitempty"`
	// Purge drops findings this pass does not re-confirm, except triaged ones.
	Purge bool `json:"purge,omitempty"`
}

// ErrScanRunning is returned when a rescan is already in progress.
var ErrScanRunning = errors.New("a scan is already running")

// Scanner drives detection over the proxy's capture store. It pulls on an
// interval rather than being called from the proxy's request path, so detection
// never runs on the goroutine serving the browser, and a rescan is the same code
// path with a different starting cursor.
type Scanner struct {
	engine    *Engine
	findings  *Store
	store     *proxy.Store
	scope     *proxy.Scope
	broadcast chan<- any

	// wake is a coalescing doorbell (capacity 1, non-blocking send) for
	// requesting an immediate pass without blocking the caller.
	wake chan struct{}

	cursor atomic.Int64

	mu     sync.Mutex
	status ScanStatus
	cancel context.CancelFunc
}

// NewScanner wires a scanner. scope may be nil (no scope gating available).
func NewScanner(engine *Engine, findings *Store, store *proxy.Store, scope *proxy.Scope, broadcast chan<- any) *Scanner {
	return &Scanner{
		engine:    engine,
		findings:  findings,
		store:     store,
		scope:     scope,
		broadcast: broadcast,
		wake:      make(chan struct{}, 1),
	}
}

// ResetCursor sets the live-scan watermark. Must be called wherever the proxy
// store rewrites its sequence numbering (Store.Clear, Store.LoadItems); a stale
// high cursor stops the loop from seeing any further request.
func (s *Scanner) ResetCursor(seq int) {
	s.cursor.Store(int64(seq))
}

// Cursor returns the current watermark.
func (s *Scanner) Cursor() int { return int(s.cursor.Load()) }

// Wake requests an immediate scan pass without blocking.
func (s *Scanner) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run drives the live scan loop until ctx is cancelled. The work is in scanOnce,
// which is synchronous and has no timing dependency.
func (s *Scanner) Run(ctx context.Context) {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
		s.scanOnce(ctx)
	}
}

// scopeFunc returns the scope predicate, or nil when unavailable.
func (s *Scanner) scopeFunc() proxy.ScopeFunc {
	if s.scope == nil {
		return nil
	}
	return s.scope.InScope
}

// scanWorkers sizes a fan-out for n items. The ceiling leaves cores for the
// proxy itself, which is the workload the operator is actually waiting on; the
// floor keeps one slow body from stalling the batch behind it.
func scanWorkers(n int) int {
	workers := runtime.NumCPU() / 2
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	// A live tick usually carries one or two captures, and spawning the whole
	// pool for those costs more than it saves.
	if workers > n {
		workers = n
	}
	return workers
}

// fanOutScan runs scanItem over items across a bounded worker pool and reports
// how many were scanned, how many findings were newly created, and whether ctx
// cancelled the pass before the producer drained.
//
// Both scan paths share this, so per-message concurrency stays out of the engine:
// scanMessage is untouched and the parallelism is strictly across captures.
// Safe because a scan reads only immutable state — Engine.Scan takes the ruleSet
// pointer under a read lock and releases it before scanning, and the snapshot is
// replaced wholesale rather than mutated. Results funnel through the
// mutex-serialized Upsert, which is cheap next to the scanning.
//
// onProgress, when non-nil, is called from the producer at most once per
// progressInterval.
func (s *Scanner) fanOutScan(
	ctx context.Context,
	items []*proxy.CapturedRequest,
	scope proxy.ScopeFunc,
	stream bool,
	onProgress func(scanned, created int),
) (scanned, created int, stopped bool) {
	if len(items) == 0 {
		return 0, 0, false
	}

	var scannedN, createdN atomic.Int64
	workers := scanWorkers(len(items))
	work := make(chan *proxy.CapturedRequest, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				createdN.Add(int64(s.scanItem(item, scope, stream)))
				scannedN.Add(1)
			}
		}()
	}

	lastProgress := time.Now()
producer:
	for _, item := range items {
		select {
		case <-ctx.Done():
			stopped = true
			break producer
		case work <- item:
		}
		if onProgress != nil && time.Since(lastProgress) >= progressInterval {
			lastProgress = time.Now()
			onProgress(int(scannedN.Load()), int(createdN.Load()))
		}
	}
	close(work)
	wg.Wait()

	return int(scannedN.Load()), int(createdN.Load()), stopped
}

// scanOnce scans up to maxPerTick newly captured requests and returns how many
// were scanned and how many new findings resulted.
func (s *Scanner) scanOnce(ctx context.Context) (scanned, newFindings int) {
	if s.store == nil || s.engine == nil || !s.engine.IsEnabled() {
		return 0, 0
	}
	cursor := int(s.cursor.Load())
	items := s.store.SinceSeq(cursor, maxPerTick)
	if len(items) == 0 {
		return 0, 0
	}

	// The watermark advances in the producer, never in a worker: SinceSeq returns
	// items in sequence order, so the maximum is known without waiting on the
	// scan, and one goroutine owning the cursor keeps the batch semantics — the
	// cursor moves once, after the batch drains — unchanged by the fan-out.
	for _, item := range items {
		if item.Seq > cursor {
			cursor = item.Seq
		}
	}

	scanned, newFindings, stopped := s.fanOutScan(ctx, items, s.scopeFunc(), true, nil)
	if stopped {
		// Leave the watermark where it was so the undispatched tail is picked up
		// next pass. Re-scanning what did complete is free: Upsert dedupes.
		return scanned, newFindings
	}

	s.cursor.Store(int64(cursor))
	if newFindings > 0 {
		s.emitSummary()
	}
	return scanned, newFindings
}

// scanItem scans one capture, stores the results, and optionally streams each new
// finding. Returns the number of newly-created findings.
func (s *Scanner) scanItem(item *proxy.CapturedRequest, scope proxy.ScopeFunc, stream bool) int {
	cfg := s.engine.Config()
	// Parsed here only to record why a body could not be read.
	if msg := Parse(item, cfg); msg.SkipReason != "" {
		s.findings.NoteSkipped(msg.SkipReason)
	}
	s.findings.NoteScanned(1)

	results := s.engine.Scan(item, scope)
	created := 0
	for _, f := range results {
		stored, isNew := s.findings.Upsert(f)
		if isNew {
			created++
		}
		if stream {
			s.emitFinding(*stored, isNew)
		}
	}
	return created
}

// emitFinding streams a single finding. The send is non-blocking and the event
// is droppable: the hub's broadcast channel is shared with request capture, and
// the UI reconciles from detect.summary.
func (s *Scanner) emitFinding(f Finding, isNew bool) {
	if s.broadcast == nil {
		return
	}
	select {
	case s.broadcast <- event.WSEvent{
		Type: "detect.finding",
		Data: map[string]any{"finding": summaryOf(f), "isNew": isNew},
	}:
	default:
	}
}

// emitSummary streams the aggregate counts.
func (s *Scanner) emitSummary() {
	if s.broadcast == nil {
		return
	}
	select {
	case s.broadcast <- event.WSEvent{Type: "detect.summary", Data: s.findings.Summary(s.engine.RuleEnabledFunc())}:
	default:
	}
}

// emit sends a lifecycle event, blocking so it cannot be lost.
func (s *Scanner) emit(kind string, data any) {
	if s.broadcast == nil {
		return
	}
	s.broadcast <- event.WSEvent{Type: kind, Data: data}
}

// Status returns a copy of the current scan status.
func (s *Scanner) Status() ScanStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Cancel stops a running rescan.
func (s *Scanner) Cancel() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// StartRescan runs the rule set over already-captured traffic in the background.
// Findings are not cleared first; Store.Upsert merges the results and keeps
// counts stable.
func (s *Scanner) StartRescan(ctx context.Context, req RescanRequest) (ScanStatus, error) {
	if s.store == nil || s.engine == nil {
		return ScanStatus{}, errors.New("detection is unavailable")
	}

	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return s.status, ErrScanRunning
	}

	items := s.store.All()
	// Exact, and deliberately not the case-insensitive substring that
	// proxy.RequestFilter.Host uses. A rescan is work, not a view: a substring
	// that happens to match several hosts silently multiplies the scan rather
	// than widening a listing. Callers enumerate the exact values with
	// history.stats first.
	if req.Scope == "host" && req.Host != "" {
		filtered := items[:0:0]
		for _, it := range items {
			if it.Host == req.Host {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}

	jobCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	jobID := proxy.GenerateID()
	s.status = ScanStatus{
		Running: true, JobID: jobID, Kind: req.Scope, Total: len(items),
		StartedAt: time.Now(), Status: "running",
	}
	status := s.status
	s.mu.Unlock()

	go s.runRescan(jobCtx, cancel, jobID, items, req)
	return status, nil
}

// runRescan executes a rescan over a snapshot of captures.
func (s *Scanner) runRescan(ctx context.Context, cancel context.CancelFunc, jobID string, items []*proxy.CapturedRequest, req RescanRequest) {
	defer cancel()

	gen := s.findings.NextGeneration()
	s.emit("detect.scan.started", map[string]any{
		"jobId": jobID, "kind": req.Scope, "total": len(items),
	})

	// Per-finding events are suppressed during a rescan; the throttled progress
	// events and the final summary carry the information instead.
	scanned, created, stopped := s.fanOutScan(ctx, items, s.scopeFunc(), false,
		func(scanned, created int) {
			s.emit("detect.scan.progress", map[string]any{
				"jobId": jobID, "scanned": scanned,
				"total": len(items), "findingsNew": created,
			})
		})

	purged := 0
	if req.Purge && !stopped {
		purged = s.findings.PurgeBelowGeneration(gen)
	}

	finalStatus := "complete"
	if stopped {
		finalStatus = "stopped"
	}
	s.mu.Lock()
	s.status.Running = false
	s.status.Scanned = scanned
	s.status.FindingsNew = created
	s.status.FinishedAt = time.Now()
	s.status.Status = finalStatus
	s.cancel = nil
	started := s.status.StartedAt
	s.mu.Unlock()

	s.emit("detect.scan.complete", map[string]any{
		"jobId": jobID, "status": finalStatus,
		"scanned": scanned, "findingsNew": created,
		"purged": purged, "durationMs": time.Since(started).Milliseconds(),
	})
	s.emitSummary()
}

// FindingSummary is the row shape sent to the UI and returned by list endpoints.
// It omits occurrences and the internal dedupe bookkeeping.
type FindingSummary struct {
	ID             string     `json:"id"`
	RuleID         string     `json:"ruleId"`
	RuleName       string     `json:"ruleName"`
	Category       Category   `json:"category"`
	Severity       Severity   `json:"severity"`
	Confidence     Confidence `json:"confidence"`
	Target         Target     `json:"target"`
	Host           string     `json:"host"`
	Method         string     `json:"method"`
	URL            string     `json:"url"`
	RequestID      string     `json:"requestId"`
	Detail         string     `json:"detail,omitempty"`
	Evidence       string     `json:"evidence"`
	RawEvidence    string     `json:"rawEvidence,omitempty"`
	EvidenceOffset int        `json:"evidenceOffset"`
	EvidenceLength int        `json:"evidenceLength"`
	EvidencePart   string     `json:"evidencePart,omitempty"`
	Count          int        `json:"count"`
	FirstSeen      time.Time  `json:"firstSeen"`
	LastSeen       time.Time  `json:"lastSeen"`
	FalsePositive  bool       `json:"falsePositive"`
	HasNotes       bool       `json:"hasNotes"`
	Truncated      bool       `json:"truncated,omitempty"`
}

// summaryOf projects a finding into its wire shape.
func summaryOf(f Finding) FindingSummary {
	return FindingSummary{
		ID: f.ID, RuleID: f.RuleID, RuleName: f.RuleName,
		Category: f.Category, Severity: f.Severity, Confidence: f.Confidence,
		Target: f.Target, Host: f.Host, Method: f.Method, URL: f.URL,
		RequestID: f.RequestID, Detail: f.Detail, Evidence: f.Evidence,
		RawEvidence:    f.RawEvidence,
		EvidenceOffset: f.EvidenceOffset, EvidenceLength: f.EvidenceLength,
		EvidencePart: f.EvidencePart,
		Count:        f.Count, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
		FalsePositive: f.FalsePositive, HasNotes: f.Notes != "",
		Truncated: f.Truncated,
	}
}

// Summaries projects a slice of findings.
func Summaries(in []Finding) []FindingSummary {
	out := make([]FindingSummary, len(in))
	for i, f := range in {
		out[i] = summaryOf(f)
	}
	return out
}
