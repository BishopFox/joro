package jsautomation

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

// The trigger dispatcher: one goroutine that decides when an armed automation runs.
//
// Shaped after detect.Scanner — a ticker plus a capacity-1 coalescing doorbell — because
// the problem is the same one. Joro's event bus drops request.captured when it is busy
// (the proxy emits with a non-blocking send), so an event cannot be the unit of work. For
// traffic the doorbell only says "look now" and a sequence cursor over the capture store
// is what is actually authoritative, which is why a dropped notification costs latency
// rather than a missed request.
//
// Every trigger delivers a *batch*. That is what makes the highest-volume one affordable:
// one run per interval handles up to maxTriggerBatch events instead of one run per event,
// so there is no process spawn per request and no queue to overflow in the common case.

const (
	dispatchInterval = 250 * time.Millisecond

	// maxTriggerBatch bounds one run's payload. Also the cursor advance, so a burst is
	// worked through over several runs rather than in one enormous ctx.trigger.
	maxTriggerBatch = 50

	// pendingCap bounds the coalescing buffer for discrete events. Past it the oldest
	// are dropped and counted — and the count is handed to the script, so an automation
	// can say in its own findings that it did not see everything.
	pendingCap = 4 * maxTriggerBatch

	// defaultMinInterval paces a trigger. One second is slow enough that a script doing
	// real work per batch cannot saturate a core, and fast enough to feel live.
	defaultMinInterval = time.Second

	// The runaway breaker. A script that sends creates traffic, creates findings, and
	// can therefore feed its own trigger through a path the cursor rule below does not
	// cover. Rather than enumerate those paths, cap the rate and stop.
	breakerWindow   = time.Minute
	breakerMaxRuns  = 30
	breakerReasonFm = "paused automatically: %d runs in the last minute, which is the runaway limit. " +
		"An automation that sends traffic can trigger itself; check its trigger and its interval, " +
		"then re-enable it."
)

// Dispatcher watches Joro's events and runs armed automations.
type Dispatcher struct {
	mgr       *Manager
	store     *proxy.Store
	broadcast chan<- any

	wake chan struct{}

	mu       sync.Mutex
	armed    map[string]*armed
	knownRev uint64
	loaded   bool
}

// armed is the dispatcher's per-automation state. None of it is persisted: a cursor
// seeded from the store head means enabling an automation does not replay an
// engagement's history at it, which is what an operator expects from arming something.
type armed struct {
	id       string
	version  string
	triggers []string
	interval time.Duration

	// isCommand changes two things about how this automation is dispatched: it is handed
	// one event rather than a batch, and its cursor always jumps to the store head. Both
	// are explained where they are applied — nextBatchLocked and finish.
	isCommand bool

	cursor int64

	pending map[string][]json.RawMessage
	dropped map[string]int

	lastRun  time.Time
	running  bool
	runTimes []time.Time
}

// NewDispatcher returns a dispatcher. broadcast may be nil.
func NewDispatcher(mgr *Manager, store *proxy.Store, broadcast chan<- any) *Dispatcher {
	return &Dispatcher{
		mgr:       mgr,
		store:     store,
		broadcast: broadcast,
		wake:      make(chan struct{}, 1),
		armed:     make(map[string]*armed),
	}
}

// Wake asks for an immediate pass. Non-blocking and coalescing: many callers between two
// passes cost one pass, which is the point.
func (d *Dispatcher) Wake() {
	if d == nil {
		return
	}
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run is the dispatcher loop. events is a subscription to Joro's event bus; it is read
// here rather than in its own goroutine so that observing an event and acting on it are
// serialized, and one automation's state needs no lock against the other path.
func (d *Dispatcher) Run(ctx context.Context, events <-chan any) {
	if d == nil || d.mgr == nil {
		return
	}
	ticker := time.NewTicker(dispatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			// Observe rings the doorbell, so the next iteration dispatches. Handling
			// the event and dispatching in the same pass would make a burst of events
			// a burst of passes.
			d.observe(ev)
			continue
		case <-ticker.C:
		case <-d.wake:
		}
		d.dispatch(ctx)
	}
}

// observe classifies one bus event.
func (d *Dispatcher) observe(ev any) {
	we, ok := ev.(event.WSEvent)
	if !ok {
		// Some producers send a bare map; all of those are team.* events, which are
		// not triggers.
		return
	}

	switch we.Type {
	case "request.captured":
		// Deliberately not read: the payload is a pointer shared with the capture
		// store, and the cursor already knows what is new. This is only a doorbell.
		d.Wake()

	case "detect.finding":
		if ref := findingRef(we.Data); ref != nil {
			d.enqueue(TriggerDetectFinding, ref)
		}

	case "fuzzer.complete":
		if ref := compact(we.Data, &campaignFields{}); ref != nil {
			d.enqueue(TriggerFuzzerComplete, ref)
		}
	}
}

// enqueue adds a reference to every automation armed for that trigger.
func (d *Dispatcher) enqueue(trigger string, ref json.RawMessage) {
	d.mu.Lock()
	for _, a := range d.armed {
		if !slices.Contains(a.triggers, trigger) {
			continue
		}
		if len(a.pending[trigger]) >= pendingCap {
			// Drop the oldest: a stale event matters less than a fresh one, and the
			// count travels to the script so the loss is visible rather than silent.
			a.pending[trigger] = a.pending[trigger][1:]
			a.dropped[trigger]++
		}
		a.pending[trigger] = append(a.pending[trigger], ref)
	}
	d.mu.Unlock()
	d.Wake()
}

// dispatch is one pass: reload the armed set if it changed, then start at most one run
// per automation.
func (d *Dispatcher) dispatch(ctx context.Context) {
	d.reload()

	now := time.Now()
	d.mu.Lock()
	type job struct {
		a       *armed
		trigger string
		payload json.RawMessage
		// batchMax is the highest capture sequence this batch actually contained, so a
		// watcher advances to exactly what it was shown rather than to an estimate.
		batchMax int
	}
	var jobs []job
	for _, a := range d.armed {
		if a.running || now.Sub(a.lastRun) < a.interval {
			continue
		}
		trigger, payload, batchMax := d.nextBatchLocked(a)
		if payload == nil {
			continue
		}
		a.running = true
		jobs = append(jobs, job{a: a, trigger: trigger, payload: payload, batchMax: batchMax})
	}
	d.mu.Unlock()

	for _, j := range jobs {
		go d.runOne(ctx, j.a, j.trigger, j.payload, j.batchMax)
	}
}

// nextBatchLocked picks the first armed trigger with work and builds its payload.
//
// Manifest order decides precedence, so an author who cares can put the trigger that
// matters first. Called with d.mu held.
//
// A command automation is handed the *newest* event rather than the batch. Its body has
// one stdin and one argv, so fifty references have nowhere to go — a command on a traffic
// trigger samples traffic rather than processing all of it. The skipped count still
// travels in the payload, and the cursor rule in finish already behaves this way for it.
func (d *Dispatcher) nextBatchLocked(a *armed) (string, json.RawMessage, int) {
	for _, t := range a.triggers {
		switch t {
		case TriggerRequestCaptured:
			if d.store == nil {
				continue
			}
			items := d.store.SinceSeq(int(a.cursor), maxTriggerBatch)
			if len(items) == 0 {
				continue
			}
			// batchMax stays the highest sequence actually read, not the one handed
			// over: a command's cursor jumps to head regardless, and reporting less
			// than was read would make a script's own accounting wrong if this line
			// were ever shared.
			batchMax := items[len(items)-1].Seq
			dropped := a.takeDropped(t)
			if a.isCommand {
				dropped += len(items) - 1
				items = items[len(items)-1:]
			}
			return t, requestBatch(items, dropped), batchMax

		default:
			refs := a.pending[t]
			if len(refs) == 0 {
				continue
			}
			n := min(len(refs), maxTriggerBatch)
			batch := refs[:n]
			a.pending[t] = refs[n:]
			dropped := a.takeDropped(t)
			if a.isCommand && len(batch) > 1 {
				dropped += len(batch) - 1
				batch = batch[len(batch)-1:]
			}
			return t, discreteBatch(t, batch, dropped), 0
		}
	}
	return "", nil, 0
}

func (a *armed) takeDropped(trigger string) int {
	n := a.dropped[trigger]
	delete(a.dropped, trigger)
	return n
}

// runOne executes one batch and settles the automation's state afterwards.
func (d *Dispatcher) runOne(ctx context.Context, a *armed, trigger string, payload json.RawMessage, batchMax int) {
	run, err := d.mgr.Invoke(ctx, InvokeRequest{
		ID:     a.id,
		Caller: AutomationPrincipal(a.id),
		// Invoke applies the automation's own host whitelist, since a trigger-fired run
		// has no launching token to inherit one from.
		Trigger:     trigger,
		TriggerData: payload,
	})
	if err != nil {
		// Busy is ordinary backpressure: leave the cursor unmoved so the next pass picks
		// the same traffic up. Discrete events were already consumed, which is the right
		// trade for something that has been coalesced anyway.
		if err != ErrBusy {
			log.Printf("[automation] %s: %v", a.id, err)
		}
		d.finish(a, nil, trigger, 0)
		return
	}
	d.finish(a, run, trigger, batchMax)
}

// finish clears the running flag, records the run for the breaker, and moves the cursor.
//
// The cursor rule is the amplification fix, and which moment it reads matters:
//
//   - A run that sent anything jumps to the store head *as of now*, which is after its
//     own traffic has been captured. That is precisely the window it caused, so it cannot
//     re-trigger itself. The cost is any browsing that happened during the run, which is
//     the honest price of sending from a traffic trigger.
//   - A pure watcher — the common case, and the one where completeness matters — advances
//     only to the highest sequence it was actually handed, so a long run swallows nothing
//     that arrived while it worked.
func (d *Dispatcher) finish(a *armed, run *Run, trigger string, batchMax int) {
	now := time.Now()

	head := 0
	if producedTraffic(a, run) && d.store != nil {
		head = d.store.LastSeq()
	}

	d.mu.Lock()
	a.running = false
	a.lastRun = now

	if run != nil && trigger == TriggerRequestCaptured {
		switch {
		case head > 0:
			a.cursor = int64(head)
		case batchMax > 0:
			a.cursor = int64(batchMax)
		}
	}

	if run != nil {
		a.runTimes = append(a.runTimes, now)
		cut := now.Add(-breakerWindow)
		for len(a.runTimes) > 0 && a.runTimes[0].Before(cut) {
			a.runTimes = a.runTimes[1:]
		}
	}
	tripped := len(a.runTimes) >= breakerMaxRuns
	count := len(a.runTimes)
	id := a.id
	d.mu.Unlock()

	if tripped {
		d.pause(id, fmt.Sprintf(breakerReasonFm, count))
	}
}

// producedTraffic reports whether this run may have added to the capture store, which is
// what decides whether the cursor jumps past its own window.
//
// The two cases answer the same question with different evidence, and the difference is
// the whole reason this is a function:
//
//   - A script's sends all go through the capability registry, so SendCalls is an exact
//     count. Zero means it read and did not write, and a pure watcher can safely advance
//     only to what it was shown.
//   - A command's traffic does not pass through the registry at all. Joro cannot see
//     whether a subprocess opened a socket, so there is no count to consult and the only
//     safe answer is to assume it sent. A curl or a scanner routed through Joro's own
//     proxy lands in the capture store, and a cursor that advanced only to what the run
//     was handed would immediately hand it its own traffic — a loop that feeds itself,
//     which is exactly what this rule exists to prevent.
//
// The cost of assuming is that a command automation on a traffic trigger skips whatever
// was captured while it ran. That is already how it behaves — nextBatchLocked hands it one
// event and counts the rest as dropped — so the two rules agree rather than compounding.
func producedTraffic(a *armed, run *Run) bool {
	if run == nil {
		return false
	}
	if a.isCommand {
		return true
	}
	return run.Result.SendCalls > 0
}

// pause stops an automation the breaker caught, and tells the operator.
//
// Enabled is left alone: it records what the operator wanted, and resuming should restore
// that rather than ask them to remember it. Paused persists to the sidecar, so a restart
// does not quietly re-arm something that was looping.
func (d *Dispatcher) pause(id, reason string) {
	store := d.mgr.Packages()
	if store == nil {
		return
	}
	if _, err := store.SetState(id, func(st *State) {
		st.Paused = true
		st.PausedReason = reason
	}); err != nil {
		log.Printf("[automation] %s: recording pause: %v", id, err)
		return
	}
	log.Printf("[automation] %s %s", id, reason)

	d.mu.Lock()
	delete(d.armed, id)
	d.mu.Unlock()

	// The one automation event worth pushing. Per-run events would be a firehose an
	// agent controls; this fires only on a state change the operator did not make, which
	// is the case where waiting for the next poll is wrong.
	if d.broadcast != nil {
		select {
		case d.broadcast <- event.WSEvent{Type: "automation.script.state", Data: map[string]any{
			"id": id, "enabled": true, "paused": true, "pausedReason": reason,
		}}:
		default:
		}
	}
}

// reload syncs the armed set with the installed set, but only when the store says
// something changed — otherwise every 250ms tick would re-read every package from disk.
func (d *Dispatcher) reload() {
	store := d.mgr.Packages()
	if store == nil {
		return
	}
	rev := store.Revision()

	d.mu.Lock()
	if d.loaded && rev == d.knownRev {
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()

	list := store.List()

	head := 0
	if d.store != nil {
		head = d.store.LastSeq()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	seen := make(map[string]struct{}, len(list))
	for _, a := range list {
		triggers := a.ArmedTriggers()
		if len(triggers) == 0 {
			continue
		}
		seen[a.Manifest.ID] = struct{}{}

		cur, ok := d.armed[a.Manifest.ID]
		if !ok {
			// A freshly armed automation starts at the head. Replaying the engagement
			// so far at something the operator just switched on would be a surprise,
			// and for a sender an expensive one.
			cur = &armed{
				id:      a.Manifest.ID,
				cursor:  int64(head),
				pending: make(map[string][]json.RawMessage),
				dropped: make(map[string]int),
			}
			d.armed[a.Manifest.ID] = cur
		}
		cur.version = a.Manifest.Version
		cur.triggers = triggers
		cur.interval = effectiveInterval(a)
		cur.isCommand = a.Manifest.IsCommand()
	}

	for id, a := range d.armed {
		if _, still := seen[id]; !still && !a.running {
			delete(d.armed, id)
		}
	}

	d.knownRev = rev
	d.loaded = true
}

// effectiveInterval takes the longer of the author's and the operator's minimum, since
// for an interval the more conservative value is the larger one — the opposite of every
// other limit, which is why it is not in ManifestLimits.
func effectiveInterval(a *Automation) time.Duration {
	ms := max(a.Manifest.MinIntervalMs, a.State.MinIntervalMs)
	if ms <= 0 {
		return defaultMinInterval
	}
	return time.Duration(ms) * time.Millisecond
}

// ---- trigger payloads ----

// requestRef is what a traffic-triggered run sees. References, not content: the script
// resolves detail with joro.http.read, where its principal is enforced. Being handed an
// event is not permission to read what it is about.
type requestRef struct {
	Seq         int    `json:"seq"`
	Method      string `json:"method"`
	Host        string `json:"host"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
}

func requestBatch(items []*proxy.CapturedRequest, dropped int) json.RawMessage {
	refs := make([]requestRef, 0, len(items))
	for _, it := range items {
		refs = append(refs, requestRef{
			Seq: it.Seq, Method: it.Method, Host: it.Host,
			URL: it.URL, Status: it.StatusCode, ContentType: it.ContentType,
		})
	}
	b, err := json.Marshal(map[string]any{"requests": refs, "dropped": dropped})
	if err != nil {
		return nil
	}
	return b
}

func discreteBatch(trigger string, refs []json.RawMessage, dropped int) json.RawMessage {
	key := "events"
	switch trigger {
	case TriggerDetectFinding:
		key = "findings"
	case TriggerFuzzerComplete:
		key = "campaigns"
	}
	b, err := json.Marshal(map[string]any{key: refs, "dropped": dropped})
	if err != nil {
		return nil
	}
	return b
}

// agentReportedRuleID mirrors capreg's agentFindingRuleID, the reserved rule under which
// findings.create files an agent's report. Duplicated rather than imported because capreg
// imports this package, so the reverse direction is a cycle.
const agentReportedRuleID = "agent-reported"

// findingFields is the intersection of the two shapes detect.finding arrives in.
type findingFields struct {
	ID       string `json:"id"`
	Host     string `json:"host,omitempty"`
	Severity string `json:"severity,omitempty"`
	RuleID   string `json:"ruleId,omitempty"`
}

type campaignFields struct {
	CampaignID string `json:"campaignId"`
	Status     string `json:"status,omitempty"`
	Completed  int64  `json:"completed,omitempty"`
	Errors     int64  `json:"errors,omitempty"`
}

// findingRef pulls the identifying fields out of a detect.finding payload.
//
// That event has two producers with different concrete types — the scanner sends a
// summary, the findings.create capability sends the whole finding — so the payload is
// re-encoded and read back through a struct holding only the fields both share. Slower
// than a type assertion and immune to the difference, which matters more: findings are
// low-volume, and a dispatcher that worked for one producer and not the other would be a
// trigger that fires for the operator's scans and not for an agent's reports.
func findingRef(data any) json.RawMessage {
	wrapper, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	f, ok := wrapper["finding"]
	if !ok {
		return nil
	}

	var fields findingFields
	raw, err := json.Marshal(f)
	if err != nil || json.Unmarshal(raw, &fields) != nil {
		return nil
	}

	// A finding an agent reported is not an engagement event, and must not run the
	// operator's code.
	//
	// findings.create is non-privileged and sits in the stock tester and triage profiles,
	// and its host is a free string with no target extractor and no scope guard. Treating
	// its broadcast as a trigger would let any token holding it induce a run — and a
	// trigger-fired run carries no launching token, so it is bounded by scope alone and
	// can reach hosts the inducing token is itself denied. That is a confused deputy
	// around the one grant meant to gate exactly this: script.invoke, which is privileged,
	// flag-gated, refused to every profile, and audited.
	if fields.RuleID == agentReportedRuleID {
		return nil
	}

	ref, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	// isNew rides along so a script can ignore a finding it has already been told about
	// without keeping its own bookkeeping.
	isNew, _ := wrapper["isNew"].(bool)
	merged, err := json.Marshal(map[string]any{"finding": json.RawMessage(ref), "isNew": isNew})
	if err != nil {
		return nil
	}
	return merged
}

// compact re-encodes a payload through dst, keeping only the fields dst declares.
func compact[T any](data any, dst *T) json.RawMessage {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return nil
	}
	out, err := json.Marshal(dst)
	if err != nil {
		return nil
	}
	return out
}
