package techfp

import (
	"context"
	"errors"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/proxy"
)

const (
	scanInterval     = 500 * time.Millisecond
	maxPerTick       = 100
	progressInterval = 500 * time.Millisecond
	// maxBodyScan caps the body handed to the deep (html/scriptSrc/meta) pass.
	// A fingerprint lives in the <head> and early markup; scanning megabytes of
	// a document body buys nothing.
	maxBodyScan = 512 * 1024
)

// ErrScanRunning is returned when a rescan is already in progress.
var ErrScanRunning = errors.New("a fingerprint scan is already running")

// ScanStatus reports an on-demand rescan.
type ScanStatus struct {
	Running    bool      `json:"running"`
	JobID      string    `json:"jobId,omitempty"`
	Scanned    int       `json:"scanned"`
	Total      int       `json:"total"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
	Status     string    `json:"status,omitempty"` // "running" | "complete" | "stopped"
}

// RescanRequest describes a backfill over captured history. Scope "host" with a
// Host re-fingerprints one host; anything else re-fingerprints all captures.
// Clear drops the derived map first (used on a project switch).
type RescanRequest struct {
	Scope string `json:"scope"`
	Host  string `json:"host,omitempty"`
	Clear bool   `json:"clear,omitempty"`
}

// Engine owns the cursor over captured traffic and the per-host technology store.
// Analysis runs here, not on the proxy's request path, for the reason detect's
// scanner gives: a browser waiting on a response must never wait on analysis, and
// a pass that pulls from the store is the same code a rescan would run.
type Engine struct {
	store     *Store
	reqs      *proxy.Store
	broadcast chan<- any

	wapp  atomic.Pointer[Wappalyzer] // built once on the loop goroutine
	ready atomic.Bool

	enabled atomic.Bool
	cursor  atomic.Int64
	wake    chan struct{}

	buildOnce sync.Once

	// Rescan machinery, mirroring echo's: one rescan at a time, with cancel.
	mu     sync.Mutex
	status ScanStatus
	cancel context.CancelFunc
}

// NewEngine constructs the engine. The database is compiled lazily on the first
// loop iteration so the ~6k RE2 compilations stay off the server's boot path.
func NewEngine(store *Store, reqs *proxy.Store, broadcast chan<- any) *Engine {
	e := &Engine{store: store, reqs: reqs, broadcast: broadcast, wake: make(chan struct{}, 1)}
	e.enabled.Store(true)
	return e
}

// Store exposes the technology store for the API and the active-scan rule.
func (e *Engine) Store() *Store { return e.store }

// Enabled reports whether fingerprinting is active.
func (e *Engine) Enabled() bool { return e.enabled.Load() }

// SetEnabled toggles fingerprinting. A disabled engine no-ops per tick, so a live
// toggle needs no restart.
func (e *Engine) SetEnabled(on bool) {
	e.enabled.Store(on)
	e.Wake()
}

// ResetCursor rewinds to seq and drops the derived map, because LoadItems
// rewrites sequence numbers and a tag filed under an old one would describe a
// different host's traffic.
func (e *Engine) ResetCursor(seq int) {
	e.cursor.Store(int64(seq))
	if seq == 0 {
		e.store.Clear()
	}
}

// Wake nudges the loop without waiting for the next tick.
func (e *Engine) Wake() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Run drives the live scan loop until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	e.build()
	if !e.ready.Load() {
		return // database failed to compile; logged in build
	}
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

func (e *Engine) build() {
	e.buildOnce.Do(func() {
		w, st, err := LoadWappalyzer()
		if err != nil {
			log.Printf("techfp: fingerprint database failed to load: %v", err)
			return
		}
		e.wapp.Store(w)
		e.ready.Store(true)
		log.Printf("techfp: fingerprint database loaded (%d technologies, %d patterns, %d dropped)",
			st.Techs, st.Patterns, st.Dropped)
	})
}

func (e *Engine) scanOnce(ctx context.Context) {
	if !e.enabled.Load() || e.reqs == nil {
		return
	}
	w := e.wapp.Load()
	if w == nil {
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
	changed := e.fanOut(ctx, w, items, false, nil)
	e.cursor.Store(int64(maxSeq))
	if changed > 0 {
		e.emitSummary()
	}
}

// StartRescan re-fingerprints captured history in the background: all hosts, or
// one when Scope is "host". Unlike the live loop it forces the deep-scan pass, so
// a host already past the per-host cap is still fully re-examined. One runs at a
// time. Pass the server-lifetime context so the job outlives the request.
func (e *Engine) StartRescan(ctx context.Context, req RescanRequest) (ScanStatus, error) {
	if e.reqs == nil {
		return ScanStatus{}, errors.New("no capture store")
	}
	e.mu.Lock()
	if e.status.Running {
		st := e.status
		e.mu.Unlock()
		return st, ErrScanRunning
	}
	items := e.reqs.All()
	// Exact host match, deliberately not the case-insensitive substring a listing
	// uses: a rescan is work, not a view, and a substring would silently multiply it.
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
	e.status = ScanStatus{Running: true, JobID: jobID, Total: len(items), StartedAt: time.Now(), Status: "running"}
	status := e.status
	e.mu.Unlock()

	if req.Clear {
		e.store.Clear()
	}
	go e.runRescan(rctx, cancel, jobID, items)
	return status, nil
}

func (e *Engine) runRescan(ctx context.Context, cancel context.CancelFunc, jobID string, items []*proxy.CapturedRequest) {
	defer cancel()
	e.build()
	w := e.wapp.Load()
	started := time.Now()
	e.emit("tech.scan.started", map[string]any{"jobId": jobID, "total": len(items)})

	scanned := 0
	if w != nil {
		scanned = e.fanOut(ctx, w, items, true, func(n int) {
			e.mu.Lock()
			e.status.Scanned = n
			e.mu.Unlock()
			e.emit("tech.scan.progress", map[string]any{"jobId": jobID, "scanned": n, "total": len(items)})
		})
	}

	state := "complete"
	if ctx.Err() != nil {
		state = "stopped"
	}
	e.mu.Lock()
	e.status.Running = false
	e.status.Scanned = scanned
	e.status.FinishedAt = time.Now()
	e.status.Status = state
	e.cancel = nil
	e.mu.Unlock()

	e.emit("tech.scan.complete", map[string]any{
		"jobId": jobID, "status": state, "scanned": scanned,
		"durationMs": time.Since(started).Milliseconds(),
	})
	e.emitSummary()
}

// Status returns a copy of the current rescan status.
func (e *Engine) Status() ScanStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
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

// fanOut fingerprints items across a bounded pool and returns how many produced a
// change. The pool needs no coordination beyond the store, which is mutexed. force
// bypasses the per-host deep-scan cap (set on a rescan); onProgress, when non-nil,
// is called from the producer at most once per progressInterval.
func (e *Engine) fanOut(ctx context.Context, w *Wappalyzer, items []*proxy.CapturedRequest, force bool, onProgress func(scanned int)) int {
	workers := scanWorkers(len(items))
	if workers <= 0 {
		return 0
	}
	work := make(chan *proxy.CapturedRequest, workers)
	var changed, scanned atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range work {
				if e.analyzeOne(w, it, force) {
					changed.Add(1)
				}
				scanned.Add(1)
			}
		}()
	}
	last := time.Now()
	for _, it := range items {
		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return int(changed.Load())
		case work <- it:
		}
		if onProgress != nil && time.Since(last) >= progressInterval {
			last = time.Now()
			onProgress(int(scanned.Load()))
		}
	}
	close(work)
	wg.Wait()
	return int(changed.Load())
}

// analyzeOne fingerprints one capture and folds the result into the host's set.
// It reports whether the host's technology set changed.
func (e *Engine) analyzeOne(w *Wappalyzer, it *proxy.CapturedRequest, force bool) bool {
	if it == nil || len(it.RespRaw) == 0 || it.Host == "" {
		return false
	}
	resp := httptools.ReadResponse(it.RespRaw)
	isHTML := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html")
	deep := isHTML && len(resp.Body) > 0 && (force || e.store.NeedsDeepScan(it.Host))

	body := resp.Body
	if deep && len(body) > maxBodyScan {
		body = body[:maxBodyScan]
	}
	in := Input{Header: resp.Header, URL: it.URL, IsHTML: deep}
	if deep {
		in.Body = body
	}
	dets := w.Fingerprint(in)
	if len(dets) == 0 {
		if deep {
			// Record the deep-scan attempt so a tech-less host does not get
			// re-scanned forever.
			e.store.Observe(it.Host, true, nil)
		}
		return false
	}
	changed := e.store.Observe(it.Host, deep, dets)
	if changed {
		e.emitHost(it.Host)
	}
	return changed
}

// emitHost streams a host's current technology set. Droppable: the UI reconciles
// from GET /tech/hosts.
func (e *Engine) emitHost(host string) {
	if e.broadcast == nil {
		return
	}
	ht, ok := e.store.Host(host)
	if !ok {
		return
	}
	select {
	case e.broadcast <- event.WSEvent{Type: "tech.detected", Data: ht}:
	default:
	}
}

func (e *Engine) emitSummary() {
	if e.broadcast == nil {
		return
	}
	hosts, techs := e.store.Summary()
	select {
	case e.broadcast <- event.WSEvent{Type: "tech.summary", Data: map[string]any{"hosts": hosts, "techs": techs}}:
	default:
	}
}

// emit sends a rescan lifecycle event, blocking so it cannot be lost (the hub
// fans out to subscribers without blocking).
func (e *Engine) emit(kind string, data any) {
	if e.broadcast == nil {
		return
	}
	e.broadcast <- event.WSEvent{Type: kind, Data: data}
}
