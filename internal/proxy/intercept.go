package proxy

import (
	"sync"
	"sync/atomic"
	"time"
)

// InterceptAction describes the decision made for an intercepted request.
type InterceptAction int

const (
	ActionForward InterceptAction = iota
	ActionDrop
)

// InterceptKind distinguishes a paused request from a paused response. Both
// phases of one transaction share the request's id and the same queue map: the
// request pause always completes (and its deferred delete runs) before the round
// trip that produces the response, so the key is never occupied twice.
type InterceptKind string

const (
	KindRequest  InterceptKind = "request"
	KindResponse InterceptKind = "response"
)

// maxPendingResponses caps concurrently paused responses. This is a runaway
// backstop, not a workflow limit: an operator resolves one at a time, but
// automated traffic with response interception left on would otherwise grow
// without bound at up to maxCaptureBody each.
const maxPendingResponses = 32

// InterceptDecision is sent back to the waiting handler goroutine.
type InterceptDecision struct {
	Action   InterceptAction
	ReqData  []byte // non-nil → replacement raw request bytes (request pauses)
	RespData []byte // non-nil → replacement raw response bytes (response pauses)
}

// InterceptMeta describes the transaction being paused. Built once per pause and
// handed to both the WS event constructor and the queue, so the bytes the
// operator sees can never drift from the bytes the queue holds.
type InterceptMeta struct {
	ID       string
	Method   string
	URL      string
	Host     string
	Protocol string
	Status   int // upstream status; response pauses only
	ReqRaw   []byte
	RespRaw  []byte // response pauses only
}

// PendingIntercept is an intercepted request or response awaiting a decision.
type PendingIntercept struct {
	ID       string        `json:"id"`
	Kind     InterceptKind `json:"kind"`
	Method   string        `json:"method"`
	URL      string        `json:"url"`
	Host     string        `json:"host"`
	Protocol string        `json:"protocol,omitempty"`
	Status   int           `json:"status,omitempty"`
	PausedAt time.Time     `json:"pausedAt"`
	ReqRaw   []byte        `json:"reqRaw"`            // set for both kinds
	RespRaw  []byte        `json:"respRaw,omitempty"` // response pauses only

	decision chan InterceptDecision
}

// InterceptQueue manages the set of paused requests and responses.
//
// The enabled flags are atomics rather than mutex-guarded fields for two
// reasons: they are read on every proxied request, and disabling a phase must
// both store the flag and drain that phase's pending pauses. A sync.RWMutex is
// not reentrant, so a mutex-guarded flag makes "set and drain" a deadlock
// waiting to be written. There is no invariant spanning a flag and the queue
// map, so they do not need a consistent snapshot.
type InterceptQueue struct {
	enabled     atomic.Bool // requests
	respEnabled atomic.Bool // responses — independent of requests

	mu      sync.RWMutex // guards queue and timeout only
	queue   map[string]*PendingIntercept
	timeout time.Duration
}

// NewInterceptQueue creates an InterceptQueue with the given auto-forward timeout.
func NewInterceptQueue(timeout time.Duration) *InterceptQueue {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &InterceptQueue{
		queue:   make(map[string]*PendingIntercept),
		timeout: timeout,
	}
}

// IsEnabled reports whether request interception is currently active.
func (q *InterceptQueue) IsEnabled() bool {
	return q.enabled.Load()
}

// IsResponseEnabled reports whether response interception is currently active.
func (q *InterceptQueue) IsResponseEnabled() bool {
	return q.respEnabled.Load()
}

// SetEnabled enables or disables request interception. Disabling releases every
// pending request pause with an unmodified forward — see SetResponseEnabled.
func (q *InterceptQueue) SetEnabled(enabled bool) {
	q.enabled.Store(enabled)
	if !enabled {
		q.DrainAll(KindRequest)
	}
}

// SetResponseEnabled enables or disables response interception. Disabling
// releases every pending response pause with an unmodified forward: a paused
// response holds an open client connection, and without the drain those
// goroutines would block until the timeout with no queue row left for the
// operator to resolve.
func (q *InterceptQueue) SetResponseEnabled(enabled bool) {
	q.respEnabled.Store(enabled)
	if !enabled {
		q.DrainAll(KindResponse)
	}
}

// SetTimeout changes the auto-forward timeout.
func (q *InterceptQueue) SetTimeout(d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.timeout = d
}

// kindEnabled reports whether the given phase is currently active.
func (q *InterceptQueue) kindEnabled(kind InterceptKind) bool {
	if kind == KindResponse {
		return q.respEnabled.Load()
	}
	return q.enabled.Load()
}

// PendingResponses reports how many responses are currently paused.
func (q *InterceptQueue) PendingResponses() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	n := 0
	for _, pi := range q.queue {
		if pi.Kind == KindResponse {
			n++
		}
	}
	return n
}

// HasCapacityForResponse reports whether another response may be paused without
// exceeding maxPendingResponses.
func (q *InterceptQueue) HasCapacityForResponse() bool {
	return q.PendingResponses() < maxPendingResponses
}

// Pause blocks the calling goroutine until a decision is made on the request or
// the timeout fires. Returns (decision, true) on explicit decision, or
// (forward, false) on timeout.
func (q *InterceptQueue) Pause(m InterceptMeta) (InterceptDecision, bool) {
	return q.pause(KindRequest, m)
}

// PauseResponse blocks the calling goroutine until a decision is made on the
// response or the timeout fires. The response body must already be buffered.
func (q *InterceptQueue) PauseResponse(m InterceptMeta) (InterceptDecision, bool) {
	return q.pause(KindResponse, m)
}

func (q *InterceptQueue) pause(kind InterceptKind, m InterceptMeta) (InterceptDecision, bool) {
	pi := &PendingIntercept{
		ID:       m.ID,
		Kind:     kind,
		Method:   m.Method,
		URL:      m.URL,
		Host:     m.Host,
		Protocol: m.Protocol,
		Status:   m.Status,
		PausedAt: timeNow(),
		ReqRaw:   m.ReqRaw,
		RespRaw:  m.RespRaw,
		decision: make(chan InterceptDecision, 1),
	}

	q.mu.Lock()
	timeout := q.timeout
	q.queue[m.ID] = pi
	q.mu.Unlock()

	// Identity-checked delete: with one map and strictly sequential phases the
	// plain delete is correct today, but checking identity makes "one phase's
	// cleanup evicts the other's entry" impossible if these blocks are ever
	// reordered or an id is reused.
	defer func() {
		q.mu.Lock()
		if cur, ok := q.queue[m.ID]; ok && cur == pi {
			delete(q.queue, m.ID)
		}
		q.mu.Unlock()
	}()

	// Re-check after registering. The toggle may have flipped (and drained)
	// between the caller's check and this registration, which would otherwise
	// block here for the full timeout with no queue row to resolve.
	if !q.kindEnabled(kind) {
		return InterceptDecision{Action: ActionForward}, false
	}

	select {
	case d := <-pi.decision:
		return d, true
	case <-time.After(timeout):
		return InterceptDecision{Action: ActionForward}, false
	}
}

// Resolve sends a decision to the goroutine waiting on id. Returns false if id
// is unknown. Phase-agnostic: at most one pause is registered per id at a time,
// and each pause site reads only the decision field it cares about.
func (q *InterceptQueue) Resolve(id string, d InterceptDecision) bool {
	q.mu.RLock()
	pi, ok := q.queue[id]
	q.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case pi.decision <- d:
		return true
	default:
		return false
	}
}

// DrainAll forwards every pending pause of the given kind unmodified and returns
// how many were released. Pass an empty kind to drain both phases.
func (q *InterceptQueue) DrainAll(kind InterceptKind) int {
	// Snapshot under the read lock, then send outside it. The sends are
	// non-blocking so holding the lock would work, but this keeps DrainAll
	// composable and the lock hold short.
	q.mu.RLock()
	targets := make([]*PendingIntercept, 0, len(q.queue))
	for _, pi := range q.queue {
		if kind == "" || pi.Kind == kind {
			targets = append(targets, pi)
		}
	}
	q.mu.RUnlock()

	n := 0
	for _, pi := range targets {
		select {
		case pi.decision <- InterceptDecision{Action: ActionForward}:
			n++
		default:
		}
	}
	return n
}

// List returns a snapshot of all currently pending requests and responses.
func (q *InterceptQueue) List() []*PendingIntercept {
	q.mu.RLock()
	defer q.mu.RUnlock()
	result := make([]*PendingIntercept, 0, len(q.queue))
	for _, pi := range q.queue {
		result = append(result, pi)
	}
	return result
}
