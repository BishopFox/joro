// Package chainrun executes the chains internal/chain describes.
//
// It is a separate package for the reason internal/apiscan is separate from
// internal/apispec: passing a send callback into chain would satisfy the import
// rule while destroying the property that makes chain worth having, which is that
// nothing in it can reach the network. internal/fuzzer and internal/detect are
// split from their model layers the same way.
//
// # Everything goes through Joro's own proxy
//
// Sends use httptools.SendViaProxy, not proxy.SendRawRequest, so every step of a
// replay is captured into History, scanned by the detect engine, entered into the
// site map, filtered by scope and rewritten by Match & Replace exactly as browser
// traffic is — and so every step comes back with a Seq the grid can link to. The
// costs are the ones that path always carries: HTTP/1.1 only, and an armed
// intercept pauses every single send.
//
// # A run is sequential, and only one runs at a time
//
// This inverts apiscan's worker pool, deliberately. The steps of a workflow are
// data-dependent, so they cannot overlap; and two variants of a checkout running
// concurrently race on the application's own state, so both produce verdicts that
// describe the interleaving rather than the application. The handler refuses a
// second run rather than queueing one, because a queue would hide the constraint.
//
// # The baseline is measured, never remembered
//
// Every run executes the baseline ordering first and compares every other variant
// against what it observed. Comparing against the recording instead would report
// every session-dependent difference — a new CSRF token, a fresh timestamp — as a
// change the mutation caused.
//
// # What two responses are compared on
//
// Both hashes are taken over the canonicalized response: chain.Canonicalize
// first folds every value the run has bound down to its variable name, so an
// order id that is different by construction on every run stops being a
// difference. That step is not optional. httptools.FingerprintResponse folds what
// its patterns recognize and an id like "ord_4025aff0ad" matches none of them, so
// without canonicalizing first every replayed step reads as "changed", every skip
// reads as "enforced", and the tab reports a vulnerable application as safe.
//
// On top of that, StructHash also folds digits and dates, which answers "did this
// still work the same way" — what a skip or a reorder asks. CanonHash keeps the
// canonical body exactly, which answers "did anything about the answer change" —
// what a repeat asks, where a total falling from 90 to 80 is the whole finding
// and StructHash maps both numbers to one placeholder.
package chainrun

import (
	"context"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/chain"
	"github.com/BishopFox/joro/internal/httptools"
)

// Status is a run's state.
type Status string

const (
	StatusRunning  Status = "running"
	StatusComplete Status = "complete"
	StatusStopped  Status = "stopped"
)

// Cell states describe one step instance's outcome against the baseline.
const (
	// CellOK means the step answered with the same structural hash the baseline
	// did: as far as this comparison can tell, the application did the same thing.
	CellOK = "ok"

	// CellChanged means it answered differently.
	CellChanged = "changed"

	// CellBlocked is the subset of changed worth naming: the baseline succeeded
	// here and this did not.
	CellBlocked = "blocked"

	// CellUnresolved means the step did not send, because a value it consumes was
	// never produced in this ordering. This is the state that makes the tab
	// trustworthy — without it a broken replay is indistinguishable from an
	// application enforcing its sequence, and the tool would report false
	// negatives as confident passes.
	CellUnresolved = "unresolved"

	// CellSkipped means the variant deliberately omitted the step.
	CellSkipped = "skipped"

	// CellError means the send itself failed.
	CellError = "error"
)

// Verdicts. The question a mutation asks differs by kind, so the answer does too.
const (
	VerdictBaseline = "baseline"

	// VerdictBypassed: the goal still succeeded with a step omitted or reordered.
	// The finding.
	VerdictBypassed = "bypassed"

	// VerdictEnforced: the goal changed or failed. The application noticed.
	VerdictEnforced = "enforced"

	// VerdictAmplified: repeating a step changed the goal's answer — a coupon
	// applied twice, a transfer counted twice.
	VerdictAmplified = "amplified"

	// VerdictIdempotent: repeating a step changed nothing.
	VerdictIdempotent = "idempotent"

	// VerdictInconclusive dominates every other verdict. A replay that broke
	// before reaching the goal says nothing about the application, and reporting
	// it as anything else fails in the direction that hides a real finding —
	// the polarity apiscan.verdictFor and trigger.Compile both settle on.
	VerdictInconclusive = "inconclusive"
)

// Bounds.
const (
	MaxRuns = 20

	DefaultDelayMs = 250
	MaxDelayMs     = 60000

	DefaultTimeoutMs = 15000
	MaxTimeoutMs     = 60000

	DefaultBudgetMs = 900000
	MaxBudgetMs     = 3600000
)

// Config is snapshotted when a run starts, so an edit to the chain mid-run
// cannot change what the run is executing or what its results describe.
type Config struct {
	ChainID  string
	Chain    *chain.Chain
	Variants []chain.Variant

	// AllowStateChanging is the arming gate. A chain containing any non-GET step
	// is refused without it.
	AllowStateChanging bool

	DelayMs   int
	TimeoutMs int
	BudgetMs  int
}

// Result is one step instance.
type Result struct {
	Index     int    `json:"index"`
	VariantID string `json:"variantId"`
	StepID    string `json:"stepId"`
	Label     string `json:"label"`
	Method    string `json:"method"`
	URL       string `json:"url"`

	// Occurrence distinguishes the instances of a repeated step: 0 is the one
	// that owns the grid slot, 1 and up live in the extras region.
	Occurrence int `json:"occurrence"`

	Cell string `json:"cell"`

	Status     int    `json:"status"`
	Len        int    `json:"len"`
	DurationMs int64  `json:"durationMs"`
	BodyHash   string `json:"bhash,omitempty"`

	// StructHash and CanonHash are both taken over the canonicalized response —
	// the copy with every bound value folded to its variable name — and they
	// answer different questions, which is why both exist.
	//
	// StructHash additionally folds digits, dates and unbound tokens, so it
	// answers "did this still work the same way": the question a skip or a
	// reorder asks. CanonHash is the canonicalized body exactly, so it preserves
	// numbers, which is the question a repeat asks — an order total falling from
	// 90 to 80 is the entire finding, and StructHash normalizes both to the same
	// digit placeholder.
	StructHash string `json:"shash,omitempty"`
	CanonHash  string `json:"chash,omitempty"`
	Words      int    `json:"words,omitempty"`
	Lines      int    `json:"lines,omitempty"`
	Note       string `json:"note,omitempty"`

	// Seq addresses the History row this send produced; 0 means it could not be
	// correlated, which is normal for a noise-filtered or out-of-scope host.
	Seq       int    `json:"seq,omitempty"`
	RequestID string `json:"requestId,omitempty"`
	SeqNote   string `json:"seqNote,omitempty"`

	// Missing names the dependencies that stopped this step sending.
	Missing []chain.Missing `json:"missing,omitempty"`

	// Captured lists sources on this step that did not fire. Not fatal here — it
	// becomes one of its consumers' Missing entries — but reported so the UI can
	// show the failure beside the step that caused it.
	Captured []string `json:"captured,omitempty"`

	Error string `json:"error,omitempty"`

	ReqRaw  []byte `json:"-"`
	RespRaw []byte `json:"-"`
}

// Run is one execution.
type Run struct {
	ID        string    `json:"id"`
	ChainID   string    `json:"chainId"`
	ChainName string    `json:"chainName"`
	CreatedAt time.Time `json:"createdAt"`
	Total     int       `json:"total"`

	// Stride is the grid width: the number of steps in the chain. Slots are
	// idx = variantIndex*Stride + chainStepIndex, which makes the grid pivot
	// index arithmetic rather than a search and means a step that never sent
	// still occupies the cell the client asks about.
	Stride   int             `json:"stride"`
	Variants []chain.Variant `json:"variants"`
	Steps    []StepHead      `json:"steps"`

	Config Config `json:"-"`

	mu         sync.RWMutex
	status     Status
	completed  int
	errors     int
	unresolved int
	bypassed   int
	results    []Result
	extras     []Result
	verdicts   map[string]Verdict
	cancel     context.CancelFunc
}

// StepHead is the grid's column header: enough to render it without the chain.
type StepHead struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Method string `json:"method"`
	Setup  bool   `json:"setup,omitempty"`
	Goal   bool   `json:"goal,omitempty"`
}

// Verdict is one variant's outcome.
type Verdict struct {
	VariantID string `json:"variantId"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Verdict   string `json:"verdict"`
	Detail    string `json:"detail,omitempty"`
}

// NewRun creates a run with its grid pre-sized.
func NewRun(id string, cfg Config, total int) *Run {
	ch := cfg.Chain
	goal, hasGoal := ch.GoalStep()

	heads := make([]StepHead, len(ch.Steps))
	for i, s := range ch.Steps {
		heads[i] = StepHead{
			ID:     s.ID,
			Label:  s.Label,
			Method: chain.MethodOf(s.ReqRaw),
			Setup:  s.Setup,
			Goal:   hasGoal && s.ID == goal.ID,
		}
	}

	stride := len(ch.Steps)
	return &Run{
		ID:        id,
		ChainID:   cfg.ChainID,
		ChainName: ch.Name,
		CreatedAt: time.Now(),
		Total:     total,
		Stride:    stride,
		Variants:  cfg.Variants,
		Steps:     heads,
		Config:    cfg,
		status:    StatusRunning,
		results:   make([]Result, stride*len(cfg.Variants)),
		verdicts:  make(map[string]Verdict, len(cfg.Variants)),
	}
}

// Status reports the run's state.
func (r *Run) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

// Counts reports progress.
func (r *Run) Counts() (completed, errors, unresolved, bypassed int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.completed, r.errors, r.unresolved, r.bypassed
}

// Results returns the grid and the extras with raw bodies stripped, which is what
// every list endpoint wants; raws are fetched one at a time by index.
func (r *Run) Results() []Result {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Result, 0, len(r.results)+len(r.extras))
	for _, res := range append(append([]Result{}, r.results...), r.extras...) {
		res.ReqRaw, res.RespRaw = nil, nil
		out = append(out, res)
	}
	return out
}

// ResultAt returns one result including its raw bodies. The index space runs
// across the grid and then the extras.
func (r *Run) ResultAt(i int) (Result, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if i < 0 {
		return Result{}, false
	}
	if i < len(r.results) {
		return r.results[i], true
	}
	if j := i - len(r.results); j < len(r.extras) {
		return r.extras[j], true
	}
	return Result{}, false
}

// Verdicts returns every variant verdict computed so far.
func (r *Run) Verdicts() []Verdict {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Verdict, 0, len(r.verdicts))
	for _, v := range r.Variants {
		if got, ok := r.verdicts[v.ID]; ok {
			out = append(out, got)
		}
	}
	return out
}

// setResult stores an outcome in its grid slot and advances the counters.
func (r *Run) setResult(i int, res Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i < 0 || i >= len(r.results) {
		return
	}
	res.Index = i
	r.results[i] = res
	r.tallyLocked(res)
}

// addExtra stores an instance with no grid slot: a repeated step's second and
// later occurrences.
func (r *Run) addExtra(res Result) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	res.Index = len(r.results) + len(r.extras)
	r.extras = append(r.extras, res)
	r.tallyLocked(res)
	return res.Index
}

// lastOccurrence returns a step's final instance within one variant.
//
// The grid holds occurrence 0, so a repeat's later sends live in extras and are
// invisible to anything pivoting by slot — including the verdict, which needs
// the send the repeat actually added.
func (r *Run) lastOccurrence(variantID, stepID string) (Result, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out Result
	found := false
	for _, res := range r.extras {
		if res.VariantID != variantID || res.StepID != stepID {
			continue
		}
		if !found || res.Occurrence > out.Occurrence {
			out, found = res, true
		}
	}
	return out, found
}

func (r *Run) tallyLocked(res Result) {
	// A skipped cell is grid filler, not work: the variant omitted the step, so
	// counting it as progress would make the bar reach the end early and make
	// completed disagree with the number of requests the run said it would send.
	if res.Cell == CellSkipped {
		return
	}
	r.completed++
	switch res.Cell {
	case CellError:
		r.errors++
	case CellUnresolved:
		r.unresolved++
	}
}

func (r *Run) setVerdict(v Verdict) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verdicts[v.VariantID] = v
	if v.Verdict == VerdictBypassed || v.Verdict == VerdictAmplified {
		r.bypassed++
	}
}

// baselineOf reads a step's baseline outcome. The baseline is always variant 0,
// so its row starts at slot 0 and a step's chain index is its slot.
func (r *Run) baselineOf(stepIdx int) (Result, bool) {
	res, ok := r.slotAt(stepIdx)
	return res, ok && res.Cell != ""
}

// slotAt reads one grid slot.
func (r *Run) slotAt(idx int) (Result, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if idx < 0 || idx >= len(r.results) {
		return Result{}, false
	}
	return r.results[idx], true
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
	// Send carries the proxy address, CA and capture store. Claims stays nil: a
	// chain run is sequential by construction, which is the one case
	// SendViaProxy documents as not needing a claim set.
	Send httptools.SendDeps

	// Broadcast is the hub's channel, carrying event.WSEvent values.
	Broadcast chan<- any
}

func clampInt(v, def, lo, hi int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
