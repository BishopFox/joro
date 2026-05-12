package proxy

import (
	"sync"
	"time"
)

// InterceptAction describes the decision made for an intercepted request.
type InterceptAction int

const (
	ActionForward InterceptAction = iota
	ActionDrop
)

// InterceptDecision is sent back to the waiting handler goroutine.
type InterceptDecision struct {
	Action  InterceptAction
	ReqData []byte // non-nil → use as replacement raw request bytes
}

// PendingRequest is an intercepted request waiting for a forward/drop decision.
type PendingRequest struct {
	ID       string `json:"id"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	Protocol string `json:"protocol,omitempty"`
	ReqRaw   []byte `json:"reqRaw"`

	decision chan InterceptDecision
}

// InterceptQueue manages the set of paused requests and the enabled/disabled toggle.
type InterceptQueue struct {
	mu      sync.RWMutex
	enabled bool
	queue   map[string]*PendingRequest
	timeout time.Duration
}

// NewInterceptQueue creates an InterceptQueue with the given auto-forward timeout.
func NewInterceptQueue(timeout time.Duration) *InterceptQueue {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &InterceptQueue{
		queue:   make(map[string]*PendingRequest),
		timeout: timeout,
	}
}

// IsEnabled reports whether interception is currently active.
func (q *InterceptQueue) IsEnabled() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.enabled
}

// SetEnabled enables or disables interception.
func (q *InterceptQueue) SetEnabled(enabled bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.enabled = enabled
}

// SetTimeout changes the auto-forward timeout.
func (q *InterceptQueue) SetTimeout(d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.timeout = d
}

// Pause blocks the calling goroutine until a decision is made or the timeout fires.
// Returns (decision, true) on explicit decision, or (forward, false) on timeout.
func (q *InterceptQueue) Pause(id, method, rawURL, host, protocol string, rawReq []byte) (InterceptDecision, bool) {
	pr := &PendingRequest{
		ID:       id,
		Method:   method,
		URL:      rawURL,
		Host:     host,
		Protocol: protocol,
		ReqRaw:   rawReq,
		decision: make(chan InterceptDecision, 1),
	}

	q.mu.Lock()
	timeout := q.timeout
	q.queue[id] = pr
	q.mu.Unlock()

	defer func() {
		q.mu.Lock()
		delete(q.queue, id)
		q.mu.Unlock()
	}()

	select {
	case d := <-pr.decision:
		return d, true
	case <-time.After(timeout):
		return InterceptDecision{Action: ActionForward}, false
	}
}

// Resolve sends a decision to the goroutine waiting on id. Returns false if id is unknown.
func (q *InterceptQueue) Resolve(id string, d InterceptDecision) bool {
	q.mu.RLock()
	pr, ok := q.queue[id]
	q.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case pr.decision <- d:
		return true
	default:
		return false
	}
}

// List returns a snapshot of all currently pending requests.
func (q *InterceptQueue) List() []*PendingRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()
	result := make([]*PendingRequest, 0, len(q.queue))
	for _, pr := range q.queue {
		result = append(result, pr)
	}
	return result
}
