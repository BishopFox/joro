package echo

import (
	"context"
	"errors"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

const (
	scanInterval     = 400 * time.Millisecond
	maxPerTick       = 100
	progressInterval = 500 * time.Millisecond
)

// ErrScanRunning is returned when a rescan is already in progress.
var ErrScanRunning = errors.New("a scan is already running")

// ScanStatus reports an on-demand pass.
type ScanStatus struct {
	Running    bool      `json:"running"`
	JobID      string    `json:"jobId,omitempty"`
	Scanned    int       `json:"scanned"`
	Total      int       `json:"total"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
	Status     string    `json:"status,omitempty"`
}

// RescanRequest describes a backfill over captured history.
type RescanRequest struct {
	Scope string `json:"scope"`
	Host  string `json:"host,omitempty"`
	Clear bool   `json:"clear,omitempty"`
}

// Engine owns the configuration, the cursor over captured traffic, and the set
// of findings minted from breakout reflections.
//
// Analysis runs here rather than on the proxy's request path for the reason
// detect's scanner gives: a browser waiting on a response must never wait on
// analysis, and a pass that pulls from the store is the same code a rescan runs.
type Engine struct {
	store     *Store
	reqs      *proxy.Store
	scope     *proxy.Scope
	findings  *detect.Store
	broadcast chan<- any
	notify    func()

	mu      sync.RWMutex
	cfg     Config
	status  ScanStatus
	cancel  context.CancelFunc
	managed map[string]string

	wake   chan struct{}
	cursor atomic.Int64
}

// NewEngine constructs the engine. notify pushes the aggregate detect summary,
// which needs the detect engine's rule-enabled predicate and so lives in the
// API layer.
func NewEngine(
	store *Store,
	reqs *proxy.Store,
	scope *proxy.Scope,
	findings *detect.Store,
	broadcast chan<- any,
	notify func(),
) *Engine {
	return &Engine{
		store: store, reqs: reqs, scope: scope, findings: findings,
		broadcast: broadcast, notify: notify,
		cfg:     DefaultConfig(),
		managed: map[string]string{},
		wake:    make(chan struct{}, 1),
	}
}

func (e *Engine) Config() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// SetConfig replaces the configuration. Turning the feature off retracts the
// findings it owns, so a disabled engine leaves nothing behind in Detect.
func (e *Engine) SetConfig(cfg Config) {
	cfg.Normalize()
	e.mu.Lock()
	wasOn := e.cfg.Enabled
	e.cfg = cfg
	e.mu.Unlock()
	if wasOn && !cfg.Enabled {
		e.retractAll()
	}
	e.Wake()
}

func (e *Engine) Enabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Enabled
}

func (e *Engine) SetEnabled(on bool) {
	cfg := e.Config()
	cfg.Enabled = on
	e.SetConfig(cfg)
}

// ResetCursor rewinds to seq. The reports keyed on the old numbering are
// dropped with them, because LoadItems rewrites sequence numbers and a report
// filed under an old one would describe a different request.
func (e *Engine) ResetCursor(seq int) {
	e.cursor.Store(int64(seq))
}

// Wake nudges the loop without waiting for the next tick.
func (e *Engine) Wake() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.scanOnce(ctx)
		case <-e.wake:
			e.scanOnce(ctx)
		}
	}
}

func (e *Engine) scopeFunc() proxy.ScopeFunc {
	if e.scope == nil {
		return nil
	}
	return e.scope.InScope
}

// scanOnce analyzes the batch of captures past the cursor. The watermark is
// advanced only after the batch drains, so an interrupted tail is re-picked
// next pass; re-analyzing a message already filed is harmless because a report
// replaces its predecessor under the same request ID.
func (e *Engine) scanOnce(ctx context.Context) {
	cfg := e.Config()
	if !cfg.Enabled || e.reqs == nil {
		return
	}
	cursor := int(e.cursor.Load())
	items := e.reqs.SinceSeq(cursor, maxPerTick)
	if len(items) == 0 {
		return
	}
	maxSeq := cursor
	for _, it := range items {
		if it.Seq > maxSeq {
			maxSeq = it.Seq
		}
	}
	scanned := e.fanOut(ctx, items, cfg, nil)
	e.cursor.Store(int64(maxSeq))
	if scanned > 0 {
		e.reconcile(cfg)
		e.emitSummary()
	}
}

func scanWorkers(n int) int {
	w := runtime.NumCPU() / 2
	if w < 2 {
		w = 2
	}
	if w > 8 {
		w = 8
	}
	if n < w {
		w = n
	}
	return w
}

// fanOut analyzes items across a bounded pool. Analysis touches no shared state
// but the store, which is why the pool needs no coordination beyond it.
func (e *Engine) fanOut(
	ctx context.Context,
	items []*proxy.CapturedRequest,
	cfg Config,
	onProgress func(scanned int),
) int {
	scope := e.scopeFunc()
	workers := scanWorkers(len(items))
	if workers <= 0 {
		return 0
	}
	work := make(chan *proxy.CapturedRequest, workers)
	var scanned atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range work {
				if e.analyzeOne(it, cfg, scope) {
					scanned.Add(1)
				}
			}
		}()
	}
	last := time.Now()
	for _, it := range items {
		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return int(scanned.Load())
		case work <- it:
		}
		if onProgress != nil && time.Since(last) >= progressInterval {
			last = time.Now()
			onProgress(int(scanned.Load()))
		}
	}
	close(work)
	wg.Wait()
	return int(scanned.Load())
}

// analyzeOne filters, analyzes and files one capture. It reports whether the
// message was analyzed, which is what the scanned counter means: a message
// skipped for scope was never looked at.
func (e *Engine) analyzeOne(it *proxy.CapturedRequest, cfg Config, scope proxy.ScopeFunc) bool {
	if it == nil || len(it.RespRaw) == 0 {
		return false
	}
	if HostExcluded(it.Host, cfg.ExcludeHosts) {
		return false
	}
	if cfg.ScopeOnly && scope != nil {
		// The URL is parsed directly rather than through detect.Parse: the scope
		// check needs only the path, and a full parse here would decompress the
		// body a moment before Analyze decompresses it again.
		host, path := it.Host, "/"
		if u, err := url.Parse(it.URL); err == nil {
			if u.Host != "" {
				host = u.Host
			}
			if u.Path != "" {
				path = u.Path
			}
		}
		if !scope(host, it.Method, path) {
			return false
		}
	}
	rep := Analyze(it, cfg)
	e.store.Add(rep)
	e.store.NoteScanned(1)
	if len(rep.Reflections) > 0 {
		e.emitReflection(rep)
	}
	return true
}

// Status reports the current or last rescan.
func (e *Engine) Status() ScanStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

// Cancel stops a running rescan.
func (e *Engine) Cancel() {
	e.mu.Lock()
	cancel := e.cancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// StartRescan analyzes captured history. It is how the map is backfilled after
// the feature is switched on, which is the common case: an operator turns it on
// once the interesting traffic is already captured.
func (e *Engine) StartRescan(ctx context.Context, req RescanRequest) (ScanStatus, error) {
	cfg := e.Config()
	if e.reqs == nil {
		return ScanStatus{}, errors.New("no capture store")
	}
	e.mu.Lock()
	if e.status.Running {
		e.mu.Unlock()
		return e.status, ErrScanRunning
	}
	items := e.reqs.All()
	if req.Scope == "host" && req.Host != "" {
		filtered := items[:0:0]
		for _, it := range items {
			if it.Host == req.Host {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}
	jobID := proxy.GenerateID()
	rctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.status = ScanStatus{
		Running: true, JobID: jobID, Total: len(items),
		StartedAt: time.Now(), Status: "running",
	}
	status := e.status
	e.mu.Unlock()

	if req.Clear {
		e.store.Clear()
	}
	go e.runRescan(rctx, cancel, jobID, items, cfg)
	return status, nil
}

func (e *Engine) runRescan(
	ctx context.Context, cancel context.CancelFunc,
	jobID string, items []*proxy.CapturedRequest, cfg Config,
) {
	defer cancel()
	started := time.Now()
	e.emit("echo.scan.started", map[string]any{"jobId": jobID, "total": len(items)})

	scanned := e.fanOut(ctx, items, cfg, func(n int) {
		e.mu.Lock()
		e.status.Scanned = n
		e.mu.Unlock()
		e.emit("echo.scan.progress", map[string]any{
			"jobId": jobID, "scanned": n, "total": len(items),
		})
	})

	stopped := ctx.Err() != nil
	state := "complete"
	if stopped {
		state = "stopped"
	}
	e.mu.Lock()
	e.status.Running = false
	e.status.Scanned = scanned
	e.status.FinishedAt = time.Now()
	e.status.Status = state
	e.cancel = nil
	e.mu.Unlock()

	e.reconcile(cfg)
	e.emitSummary()
	e.emit("echo.scan.complete", map[string]any{
		"jobId": jobID, "status": state, "scanned": scanned,
		"durationMs": time.Since(started).Milliseconds(),
	})
}

func (e *Engine) emit(typ string, data map[string]any) {
	if e.broadcast == nil {
		return
	}
	e.broadcast <- event.WSEvent{Type: typ, Data: data}
}

// emitReflection is droppable: a busy sweep must not back-pressure the proxy,
// and the table resyncs on reconnect.
func (e *Engine) emitReflection(rep *Report) {
	if e.broadcast == nil {
		return
	}
	select {
	case e.broadcast <- event.WSEvent{Type: "echo.reflection", Data: map[string]any{
		"requestId":   rep.RequestID,
		"host":        rep.Host,
		"reflections": len(rep.Reflections),
		"breakouts":   rep.Breakouts,
	}}:
	default:
	}
}

func (e *Engine) emitSummary() {
	if e.broadcast == nil {
		return
	}
	select {
	case e.broadcast <- event.WSEvent{Type: "echo.summary", Data: e.store.Summary()}:
	default:
	}
}
