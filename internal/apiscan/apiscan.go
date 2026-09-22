// Package apiscan drives requests built from an API description document.
//
// It is separate from internal/apispec on purpose. apispec is a leaf: it parses
// and projects, imports nothing from the rest of Joro, and cannot send. This
// package is where the worker pool, the rate limiter, the budget, the claim set
// and the event shapes live — none of which belong in a package whose reason to
// exist is that a parser for another description language can be a sibling file
// returning the same *apispec.Spec. Passing a send callback into apispec would
// satisfy the import rule while breaking that one. internal/fuzzer and
// internal/detect are split the same way.
//
// # One runner, not two
//
// A scan is an auth matrix with a single profile. The work item is a pair of one
// operation and one profile; a scan enqueues len(ops), a matrix enqueues
// len(ops) x len(profiles), and the execution is identical. Only the view
// differs. Two runners would duplicate the pool, the limiter, the claim set and
// the results shape, would drift, and would leave two places for the destructive
// gate to be forgotten.
//
// # Everything goes through Joro's own proxy
//
// Sends use httptools.SendViaProxy, so every request is captured into History,
// scanned by the detect engine, entered into the site map, filtered by scope and
// rewritten by Match & Replace and Custom Data. Scanning an API's whole surface
// is therefore the act that populates the rest of the tool, which is the reason
// this feature is worth having inside Joro rather than beside it. The costs come
// with it: HTTP/1.1 only, an armed request intercept pauses every send in the
// operator's queue, and a large sweep occupies rows in a capture ring buffer.
package apiscan

import (
	"context"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/apispec"
	"github.com/BishopFox/joro/internal/httptools"
)

// Kind is what a run does.
type Kind string

const (
	KindScan      Kind = "scan"
	KindMatrix    Kind = "matrix"
	KindDiscovery Kind = "discovery"
)

// Status is a run's lifecycle state.
type Status string

const (
	StatusRunning  Status = "running"
	StatusComplete Status = "complete"
	StatusStopped  Status = "stopped"
)

// Caps. Sized against the fuzzer, the way httptools' batch caps are: past a few
// thousand rows the right answer is "drive the fuzzer", and the refusal says so.
const (
	MaxRequestsPerRun = 2000
	MaxProfiles       = 8
	MaxRuns           = 20
	MaxSpecs          = 8

	DefaultConcurrency = 4
	MaxConcurrency     = 20
	MaxRatePerSec      = 50

	DefaultTimeoutMs = 10000
	MaxTimeoutMs     = 60000
	DefaultBudgetMs  = 600000
	MaxBudgetMs      = 1800000

	// Discovery runs hotter than a scan: the candidates are unauthenticated GETs
	// against one host, and a scan's default of 4 would make a full sweep crawl.
	DefaultDiscoveryConcurrency = 10
	MaxDiscoveryFollows         = 50
	MaxFollowDepth              = 3

	// ChallengeLimit stops a sweep once a WAF is clearly answering. Continuing
	// spends thousands of requests to learn nothing, and looks exactly like the
	// attack the WAF is there to stop.
	ChallengeLimit = 20
)

// Profile is one authentication state a run tests under.
type Profile struct {
	ID    string `json:"id"`
	Label string `json:"label"`

	// Rank orders profiles by privilege, 0 being anonymous. It is what makes a
	// matrix verdict a statement rather than a comparison of two arbitrary
	// credential sets: "a lower rank reached what only a higher rank should"
	// needs an ordering to mean anything.
	Rank int `json:"rank"`

	// Auth never leaves the process. A run result names the profile; it never
	// carries what satisfied it.
	Auth apispec.Auth `json:"-"`
}

// Config is everything a run needs, snapshotted at start so an edit to the spec
// mid-run cannot change what is being sent.
type Config struct {
	Kind   Kind
	SpecID string

	Server apispec.Server
	Ops    []apispec.Operation
	Values map[string]apispec.Values // keyed by operation ID

	Profiles []Profile

	Concurrency int
	RatePerSec  float64
	TimeoutMs   int
	BudgetMs    int

	UserAgent string

	// AllowDestructive and Methods are the two halves of the safety gate. They
	// are configuration rather than a parse-time skip, because the operator must
	// be able to see the whole API surface and then tick the one they meant.
	AllowDestructive bool
	Methods          []string

	// Discovery only.
	Scheme       string
	Host         string
	BasePath     string
	CandidateSet apispec.CandidateSet
	StopOnFirst  bool
}

// Triage is the three-band rubric, computed server-side and shipped on the
// result so the frontend never recomputes it — one fewer mirror to keep in sync.
type Triage string

const (
	TriageGood Triage = "good" // 2xx: the request was accepted
	TriageBad  Triage = "bad"  // 401/403/404: refused or absent
	TriageWarn Triage = "warn" // everything else, including transport failure
)

// TriageOf applies the rubric. sj's colouring is the same shape; the names are
// chosen so the UI can pick glyph and colour without a second table.
func TriageOf(status int, err string) Triage {
	if err != "" {
		return TriageWarn
	}
	switch {
	case status >= 200 && status < 300:
		return TriageGood
	case status == 401 || status == 403 || status == 404:
		return TriageBad
	default:
		return TriageWarn
	}
}

// Result is one work item's outcome. A skipped item still occupies its slot, so
// the client can correlate every row back to what it asked for.
type Result struct {
	Index     int    `json:"index"`
	OpID      string `json:"opId,omitempty"`
	ProfileID string `json:"profileId,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	URL       string `json:"url,omitempty"`

	// ReqPath is the origin-form actually rendered — path and query, every
	// placeholder resolved. Path stays the document's template, because that is
	// what a row correlates back to and what a skipped row has instead; ReqPath is
	// what the operator reads to see the values that went out, without opening the
	// row. Empty when the item never rendered.
	ReqPath string `json:"reqPath,omitempty"`

	// Seq and RequestID address the History row this send produced. Seq is 0 and
	// RequestID empty when the send was not captured, which is a normal outcome
	// — a noise-filtered host, or one outside the proxy's capture scope — and
	// SeqNote says which.
	Seq       int    `json:"seq"`
	RequestID string `json:"requestId,omitempty"`
	SeqNote   string `json:"seqNote,omitempty"`

	Status     int    `json:"status"`
	Len        int    `json:"len"`
	DurationMs int64  `json:"ms"`
	BodyHash   string `json:"bhash,omitempty"`
	StructHash string `json:"shash,omitempty"`
	Words      int    `json:"words,omitempty"`
	Lines      int    `json:"lines,omitempty"`
	Note       string `json:"note,omitempty"`
	Triage     Triage `json:"triage"`

	Error   string `json:"error,omitempty"`
	Skipped string `json:"skipped,omitempty"` // destructive | method | budget | render

	// Discovery only.
	ContentType string           `json:"contentType,omitempty"`
	BodyKind    apispec.BodyKind `json:"bodyKind,omitempty"`
	SpecTitle   string           `json:"specTitle,omitempty"`
	SpecFormat  string           `json:"specFormat,omitempty"`
	SpecOps     int              `json:"specOps,omitempty"`

	ReqRaw  []byte `json:"-"`
	RespRaw []byte `json:"-"`
}

// Run is one execution. Counters are read while it is in flight, so every
// accessor takes the lock.
type Run struct {
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	SpecID    string    `json:"specId,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	Total     int       `json:"total"`

	Config Config `json:"-"`

	mu         sync.RWMutex
	status     Status
	completed  int
	errors     int
	skipped    int
	hits       int
	challenges int
	results    []Result
	cancel     context.CancelFunc
}

// NewRun creates a run in the running state with its result slots pre-sized.
//
// Slots are indexed, never appended: idx = opIndex*len(profiles) + profileIndex.
// That makes the matrix pivot index arithmetic rather than a search, and it
// means a send that failed still occupies the slot the client asked about.
func NewRun(id string, cfg Config, total int) *Run {
	return &Run{
		ID:        id,
		Kind:      cfg.Kind,
		SpecID:    cfg.SpecID,
		CreatedAt: time.Now(),
		Total:     total,
		Config:    cfg,
		status:    StatusRunning,
		results:   newResults(cfg.Kind, total),
	}
}

// newResults sizes the result slice for how the run fills it. A scan and a
// matrix write by index, so theirs is pre-sized; discovery appends, so a
// pre-sized slice would leave `total` blank rows in front of every real one.
func newResults(kind Kind, total int) []Result {
	if kind == KindDiscovery {
		return make([]Result, 0, total)
	}
	out := make([]Result, total)
	// Each slot knows its position before anything fills it: a run is read while
	// still going, and an unfilled slot carrying index 0 would claim row 0.
	for i := range out {
		out[i].Index = i
	}
	return out
}

// Status reports the run's state.
func (r *Run) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

// Counts reports progress.
func (r *Run) Counts() (completed, errors, skipped, hits int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.completed, r.errors, r.skipped, r.hits
}

// Results returns a copy of the result slice with raw bodies stripped, which is
// what every list endpoint wants; raws are fetched one at a time by index.
func (r *Run) Results() []Result {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Result, len(r.results))
	for i, res := range r.results {
		res.ReqRaw, res.RespRaw = nil, nil
		out[i] = res
	}
	return out
}

// ResultAt returns one result including its raw bodies.
func (r *Run) ResultAt(i int) (Result, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if i < 0 || i >= len(r.results) {
		return Result{}, false
	}
	return r.results[i], true
}

// setResult stores one outcome and advances the counters.
//
// Takes a pointer because the caller broadcasts the same value it stored, and
// Index is the only thing addressing a row: stamping it on a copy would leave
// every emitted result at index 0, collapsing a whole run onto one row in the
// client. The signature is what carries that obligation to the next caller.
func (r *Run) setResult(i int, res *Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i < 0 || i >= len(r.results) {
		return
	}
	res.Index = i
	r.results[i] = *res
	r.completed++
	switch {
	case res.Error != "":
		r.errors++
	case res.Skipped != "":
		r.skipped++
	}
	if res.BodyKind == apispec.KindSpec {
		r.hits++
	}
}

// appendResult stores an outcome whose index is not known in advance, which is
// discovery's shape: a followed reference is found mid-run, not enumerated.
// Pointer for the reason setResult is.
func (r *Run) appendResult(res *Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res.Index = len(r.results)
	r.results = append(r.results, *res)
	r.completed++
	if res.Error != "" {
		r.errors++
	}
	if res.BodyKind == apispec.KindSpec {
		r.hits++
	}
	if r.completed > r.Total {
		r.Total = r.completed
	}
}

// noteChallenge counts a WAF interstitial and reports whether the run should
// give up. The counter lives on the Run rather than in a package variable, so
// two concurrent runs cannot exhaust each other's budget — sj keeps the
// equivalent as package state.
func (r *Run) noteChallenge() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges++
	return r.challenges >= ChallengeLimit
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
	// Send carries the proxy address, CA and capture store. Claims is filled in
	// per run by Execute; a caller must not share one across runs.
	Send httptools.SendDeps

	// Broadcast is the hub's channel. It is chan<- any, matching
	// api.Hub.Broadcast and fuzzer.Run, and carries event.WSEvent values.
	Broadcast chan<- any
}

// clampInt keeps a client-supplied knob inside its bounds.
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
