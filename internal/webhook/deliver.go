package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/event"
)

// Delivery: the half that puts bytes on the wire.
//
// Matching happens on the goroutine draining Joro's event bus and must stay cheap, so it only
// enqueues. Everything expensive — rendering, the request, retries, backoff — happens here,
// behind a bounded queue and a small worker pool.
//
// The queue drops the oldest when it fills and counts what it dropped, and the count rides in
// the next envelope. That is the notification contract stated honestly: a webhook is allowed
// to tell a receiver less than everything, and a receiver is entitled to know that it did.
// The alternative — blocking to keep up — would push back through the bus into the proxy,
// which is exactly what Hub.Subscribe's non-blocking send exists to prevent.

const (
	// pumpInterval is how often pending queues are examined. Fast enough that a notification
	// feels immediate, slow enough that an idle Joro does nothing.
	pumpInterval = 250 * time.Millisecond

	// queueCap bounds one webhook's pending events.
	queueCap = 200

	// workers bounds concurrent in-flight deliveries across every webhook. Small: these are
	// notifications to a handful of endpoints, and a slow receiver must not be able to make
	// Joro hold hundreds of sockets open.
	workers = 4

	// retryBase is the first backoff. Doubling from there, so the default two retries wait
	// half a second and then one.
	retryBase = 500 * time.Millisecond

	// logSize is how many attempts one webhook remembers, for the editor's delivery list.
	// In memory only: a delivery log is diagnostics, and persisting it would make
	// webhooks.json grow without bound and hold response bodies from third parties.
	logSize = 20

	// The runaway breaker. A misconfigured trigger on request.captured can match every
	// request on a busy engagement; minInterval paces that, but a webhook that is still
	// delivering at this rate an hour later is a configuration nobody meant, and a
	// notification channel is exactly where that becomes someone else's problem too.
	breakerWindow    = time.Minute
	breakerMaxSends  = 60
	breakerReasonFmt = "paused automatically: %d deliveries in the last minute, which is the " +
		"runaway limit. Narrow this webhook's trigger or raise its minimum interval, then " +
		"switch it back on."
)

// Delivery is one attempt, as the editor lists it.
type Delivery struct {
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	Event   string    `json:"event"`
	Trigger string    `json:"trigger,omitempty"`

	// Events is how many events this delivery carried, Dropped how many the queue lost
	// before it.
	Events  int `json:"events"`
	Dropped int `json:"dropped,omitempty"`

	Attempts   int    `json:"attempts"`
	Status     int    `json:"status,omitempty"`
	DurationMs int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// ClientFactory returns the client one delivery uses. A function rather than a client so the
// per-webhook InsecureTLS opt-in is honored without this package building a tls.Config, which
// is the rule internal/proxy/tlsconfig.go states.
type ClientFactory func(insecure bool) http.Client

// Deliverer paces, renders and sends.
type Deliverer struct {
	store     *Store
	client    ClientFactory
	instance  string
	broadcast chan<- any

	// armed reads the compiled webhook the dispatcher holds, so a template is parsed once
	// per edit rather than once per delivery and a webhook that was deleted or broken while
	// its events waited is not delivered from a stale copy. Set once by NewDispatcher, which
	// owns that cache; a function rather than a back-pointer so the dependency runs one way.
	armed func(id string) (Webhook, *Template, bool)

	wake chan struct{}
	jobs chan job

	// fires bounds how often one principal may fire a webhook by hand. See fire.go for why
	// the limit cannot live in the run's send budget.
	fires *fireLimiter

	mu      sync.Mutex
	pending map[string]*queue
	logs    map[string][]Delivery
}

// queue is one webhook's pending work and pacing state.
type queue struct {
	events  []Event
	dropped int

	last  time.Time
	sends []time.Time

	// inflight stops a slow receiver from being handed a second delivery while the first is
	// still going, which is what would turn a timeout into a growing pile of sockets.
	inflight bool
}

// NewDeliverer returns a deliverer. broadcast may be nil.
func NewDeliverer(store *Store, client ClientFactory, instance string, broadcast chan<- any) *Deliverer {
	return &Deliverer{
		store:     store,
		client:    client,
		instance:  instance,
		broadcast: broadcast,
		wake:      make(chan struct{}, 1),
		jobs:      make(chan job, workers*2),
		fires:     newFireLimiter(),
		pending:   map[string]*queue{},
		logs:      map[string][]Delivery{},
	}
}

// Enqueue adds one matched event to a webhook's queue. Called on the dispatcher goroutine, so
// it never blocks and never does I/O.
func (d *Deliverer) Enqueue(id string, ev Event) {
	d.mu.Lock()
	q := d.pending[id]
	if q == nil {
		q = &queue{}
		d.pending[id] = q
	}
	if len(q.events) >= queueCap {
		// Drop the oldest: a stale event matters less than a fresh one, and the count
		// travels to the receiver so the loss is visible rather than silent.
		q.events = q.events[1:]
		q.dropped++
	}
	q.events = append(q.events, ev)
	d.mu.Unlock()

	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Forget drops a webhook's queue and log, for one that was deleted or disabled.
func (d *Deliverer) Forget(id string) {
	d.mu.Lock()
	delete(d.pending, id)
	delete(d.logs, id)
	d.mu.Unlock()
}

// Log returns a webhook's recent attempts, newest first.
func (d *Deliverer) Log(id string) []Delivery {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries := d.logs[id]
	out := make([]Delivery, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		out = append(out, entries[i])
	}
	return out
}

// job is one delivery handed to a worker.
type job struct {
	webhook Webhook
	tpl     *Template
	events  []Event
	dropped int
}

// Run starts the pump and the worker pool, and blocks until ctx is cancelled.
func (d *Deliverer) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range d.jobs {
				d.deliver(ctx, j)
			}
		}()
	}

	ticker := time.NewTicker(pumpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			close(d.jobs)
			wg.Wait()
			return
		case <-ticker.C:
		case <-d.wake:
		}
		d.pump()
	}
}

// pump hands out at most one delivery per webhook per pass, respecting each one's minimum
// interval.
//
// It takes the compiled set from the dispatcher's cache rather than re-reading the store, so
// a template is parsed once per edit rather than once per delivery; see Dispatcher.armedFor.
func (d *Deliverer) pump() {
	now := time.Now()

	if d.armed == nil {
		// No dispatcher wired, so nothing is armed and there is nothing to render with.
		// NewDispatcher sets this before Run is ever started; the guard is here so the
		// ordering is not silently load-bearing.
		return
	}

	d.mu.Lock()
	var (
		jobs    []job
		tripped []trip
	)
	for id, q := range d.pending {
		if q.inflight || len(q.events) == 0 {
			continue
		}
		w, tpl, ok := d.armed(id)
		if !ok {
			// Deleted, disabled or newly broken while its events waited. Drop them rather
			// than hold them: they are stale by the time it comes back.
			q.events, q.dropped = nil, 0
			continue
		}
		if now.Sub(q.last) < time.Duration(w.MinIntervalMs)*time.Millisecond {
			continue
		}

		n := len(q.events)
		if w.Delivery == DeliveryEach {
			n = 1
		} else if n > MaxBatch {
			n = MaxBatch
		}
		// One request per event still leaves the rest in the queue; they go out on later
		// passes, paced by the interval, rather than being coalesced away.
		batch := q.events[:n]
		q.events = q.events[n:]
		dropped := q.dropped
		q.dropped = 0

		q.inflight = true
		q.last = now
		q.sends = append(q.sends, now)
		cut := now.Add(-breakerWindow)
		for len(q.sends) > 0 && q.sends[0].Before(cut) {
			q.sends = q.sends[1:]
		}

		jobs = append(jobs, job{webhook: w, tpl: tpl, events: batch, dropped: dropped})

		if len(q.sends) >= breakerMaxSends {
			tripped = append(tripped, trip{id: id, count: len(q.sends)})
			q.events, q.sends = nil, nil
		}
	}
	d.mu.Unlock()

	for _, j := range jobs {
		select {
		case d.jobs <- j:
		default:
			// Every worker is busy. Put the events back and try on the next pass rather
			// than blocking the pump, which also drains the doorbell.
			d.requeue(j)
		}
	}
	for _, t := range tripped {
		d.trip(t.id, t.count)
	}
}

// trip is one webhook the breaker caught this pass, applied after the lock is released
// because pausing writes the store.
type trip struct {
	id    string
	count int
}

func (d *Deliverer) requeue(j job) {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := d.pending[j.webhook.ID]
	if q == nil {
		return
	}
	q.inflight = false
	q.dropped += j.dropped

	// Un-count the send. pump records one before it knows a worker will take the job, so a
	// job that came back has to give the slot up — otherwise the breaker trips on deliveries
	// that never happened and says so in a message that is then simply false. q.last is left
	// where it is: it only delays the retry by one interval.
	if n := len(q.sends); n > 0 {
		q.sends = q.sends[:n-1]
	}

	// Built fresh rather than appended onto j.events. That slice is a window into the same
	// backing array q.events was cut from, so appending to it writes through the queue it is
	// being merged back into.
	merged := make([]Event, 0, len(j.events)+len(q.events))
	merged = append(merged, j.events...)
	merged = append(merged, q.events...)
	if len(merged) > queueCap {
		q.dropped += len(merged) - queueCap
		merged = merged[len(merged)-queueCap:]
	}
	q.events = merged
}

// deliver renders one job and sends it, retrying on a failure worth retrying.
func (d *Deliverer) deliver(ctx context.Context, j job) {
	start := time.Now()
	rec := Delivery{
		ID:      newDeliveryID(),
		At:      start,
		Event:   j.events[0].On,
		Trigger: j.events[0].Ref,
		Events:  len(j.events),
		Dropped: j.dropped,
	}

	body, err := d.render(j)
	if err != nil {
		rec.Error = err.Error()
		d.finish(j.webhook.ID, rec, start)
		return
	}

	client := d.client(j.webhook.InsecureTLS)
	// The client carries a transport of its own, built per delivery so a SOCKS setting the
	// operator changed applies to the next one — TransportConfig snapshots its dialer when
	// asked, so a cached client would keep the old one. The cost is that its idle pool has
	// no owner once this returns, and a hand-built http.Transport has no IdleConnTimeout,
	// so the socket would sit open forever. One delivery per second is enough to run a Joro
	// out of file descriptors that way.
	defer client.CloseIdleConnections()

	timeout := time.Duration(j.webhook.TimeoutMs) * time.Millisecond

	backoff := retryBase
	for attempt := 0; attempt <= j.webhook.Retries; attempt++ {
		rec.Attempts = attempt + 1

		status, sendErr := d.send(ctx, &client, timeout, j, rec.ID, body)
		rec.Status = status
		rec.Error = ""
		if sendErr != nil {
			rec.Error = sendErr.Error()
		}

		if sendErr == nil && status < 500 && status != http.StatusTooManyRequests {
			// 2xx and 3xx are success; a 4xx other than 429 is the receiver saying the
			// request is wrong, and repeating it will not make it right.
			break
		}
		if attempt == j.webhook.Retries || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff *= 2
	}

	d.finish(j.webhook.ID, rec, start)
}

// render builds one delivery's bytes.
func (d *Deliverer) render(j job) ([]byte, error) {
	lead := j.events[0]
	c := renderContext{
		Event:    lead.On,
		Trigger:  lead.Ref,
		Webhook:  j.webhook.Name,
		Instance: d.instance,
		At:       lead.At,
		Fields:   lead.subject(),
		Summary:  lead.Summary,
	}
	if len(j.events) > 1 {
		c.Summary = fmt.Sprintf("%s (and %d more)", lead.Summary, len(j.events)-1)
	}

	refs := make([]map[string]any, 0, len(j.events))
	for _, e := range j.events {
		ref := map[string]any{"event": e.On, "trigger": e.Ref, "summary": e.Summary}
		for k, v := range e.Fields {
			ref[k] = v
		}
		refs = append(refs, ref)
	}
	return renderBody(&j.webhook, j.tpl, c, refs, j.dropped)
}

// send issues one attempt and returns the status code.
func (d *Deliverer) send(ctx context.Context, client *http.Client, timeout time.Duration,
	j job, deliveryID string, body []byte) (int, error) {

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	w := j.webhook
	req, err := http.NewRequestWithContext(ctx, w.Method, w.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "joro/"+d.instance)
	req.Header.Set(HeaderEvent, j.events[0].On)
	req.Header.Set(HeaderTrigger, j.events[0].Ref)
	req.Header.Set(HeaderDelivery, deliveryID)
	req.Header.Set(HeaderTimestamp, ts)

	for _, h := range w.Headers {
		req.Header.Set(h.Name, h.Value)
	}
	switch w.Auth.Kind {
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+w.Auth.Token)
	case AuthBasic:
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
			[]byte(w.Auth.User+":"+w.Auth.Token)))
	case AuthHeader:
		req.Header.Set(w.Auth.Header, w.Auth.Token)
	}
	if w.Signing.Enabled {
		req.Header.Set(w.Signing.Header, sign(w.Signing.Secret, ts, body))
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused, and discard it: a receiver's
	// response body is not Joro's to keep.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("%s", resp.Status)
	}
	return resp.StatusCode, nil
}

// sign is HMAC-SHA256 over "<timestamp>.<body>".
//
// The timestamp is inside the signed string rather than only in its own header, which is what
// makes it worth checking: a receiver verifying the body alone will accept a captured delivery
// replayed at any time.
func sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// record adds one attempt to a webhook's log.
//
// Separate from finish because a fire and a test are not queue work: they are synchronous,
// they were never handed out by the pump, and clearing the in-flight flag for one of them
// would release a queued delivery that is still on the wire — handing a slow receiver the
// second concurrent request the flag exists to prevent.
func (d *Deliverer) record(id string, rec Delivery, start time.Time) {
	rec.DurationMs = time.Since(start).Milliseconds()

	d.mu.Lock()
	entries := append(d.logs[id], rec)
	if len(entries) > logSize {
		entries = entries[len(entries)-logSize:]
	}
	d.logs[id] = entries
	d.mu.Unlock()
}

// finish records a queued delivery and releases its in-flight slot.
func (d *Deliverer) finish(id string, rec Delivery, start time.Time) {
	d.record(id, rec, start)

	d.mu.Lock()
	if q := d.pending[id]; q != nil {
		q.inflight = false
	}
	d.mu.Unlock()

	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// trip pauses a webhook the breaker caught, and tells the operator.
//
// Enabled is left alone: it records what the operator wanted, and resuming should restore that
// rather than ask them to remember it. Paused persists, so a restart does not quietly re-arm
// something that was flooding a channel.
func (d *Deliverer) trip(id string, count int) {
	reason := fmt.Sprintf(breakerReasonFmt, count)
	if _, err := d.store.SetState(id, func(w *Webhook) {
		w.Paused = true
		w.PausedReason = reason
	}); err != nil {
		log.Printf("[webhook] %s: recording pause: %v", id, err)
		return
	}
	log.Printf("[webhook] %s %s", id, reason)

	// The only webhook event on the bus. Per-delivery events would be a firehose; this fires
	// only on a state change the operator did not make, which is the case where waiting for
	// the next poll is wrong.
	if d.broadcast != nil {
		select {
		case d.broadcast <- event.WSEvent{Type: "webhook.state", Data: map[string]any{
			"id": id, "enabled": true, "paused": true, "pausedReason": reason,
		}}:
		default:
		}
	}
}

func newDeliveryID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}
