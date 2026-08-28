package jsautomation

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/jsruntime"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/trigger"
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

	// maxTriggerScan bounds how many captures one pass examines to fill that batch.
	// Larger than the batch because conditions reject: an automation watching for one
	// interesting response in a page load's worth of assets would otherwise advance
	// fifty captures per pass and fall steadily behind live traffic.
	maxTriggerScan = 500

	// maxScanBytes bounds the content one pass reads across every armed automation.
	// Body conditions run on the dispatcher goroutine, which also drains Joro's event
	// bus, so this is what stops a burst of large responses from stalling it. Hitting it
	// costs latency and nothing else: the cursor stays at what was actually examined and
	// the next pass resumes there.
	maxScanBytes = 8 << 20

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

	// subjects memoizes one pass's parsed captures, so ten automations watching the same
	// traffic decompress each body once between them rather than ten times. Cleared at
	// the top of every pass: it is a per-pass scratch, not a cache of the store, and
	// holding parsed bodies between passes would be a second copy of the ring buffer.
	subjects map[int]trigger.Subject

	// triggers resolves a reference to its definition. Nil is tolerated and means only
	// the built-in events are available, which is what a Joro with no trigger file has.
	triggers  *trigger.Store
	knownTrig uint64

	// reported remembers the last problem logged for each automation's trigger, so a
	// broken one is reported when it breaks rather than on every recompile. Recompiles
	// are frequent and unrelated to the problem — every finished run writes a sidecar,
	// which moves the package revision — so without this a single unreadable trigger
	// fills the log at the dispatch rate.
	reported map[string]string
}

// armed is the dispatcher's per-automation state. None of it is persisted: a cursor
// seeded from the store head means enabling an automation does not replay an
// engagement's history at it, which is what an operator expects from arming something.
type armed struct {
	id      string
	version string

	// triggers is the armed set in manifest order, each with its conditions already
	// compiled. Rebuilt in reload, never on the dispatch path, so a body regex is
	// compiled once per edit rather than once per candidate.
	triggers []armedTrigger
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

// armedTrigger is one live subscription: the reference the manifest names, the event it
// resolved to, and the compiled filter deciding which of those events is worth a run.
//
// ref and on differ whenever a custom trigger is involved, and both are needed: the
// operator's per-trigger switch keys on the reference, while the dispatcher's batching and
// cursor rules key on the event.
type armedTrigger struct {
	ref  string
	on   string
	when *trigger.Compiled
}

// find returns the compiled conditions for one event, and whether this automation is
// armed for it at all.
func (a *armed) find(on string) (*trigger.Compiled, bool) {
	for _, t := range a.triggers {
		if t.on == on {
			return t.when, true
		}
	}
	return nil, false
}

// NewDispatcher returns a dispatcher. broadcast may be nil.
func NewDispatcher(mgr *Manager, store *proxy.Store, broadcast chan<- any) *Dispatcher {
	d := &Dispatcher{
		mgr:       mgr,
		store:     store,
		broadcast: broadcast,
		wake:      make(chan struct{}, 1),
		armed:     make(map[string]*armed),
		subjects:  make(map[int]trigger.Subject),
		reported:  make(map[string]string),
	}
	if mgr != nil {
		mgr.WatchRuns(d)
	}
	return d
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
			d.enqueue(TriggerDetectFinding, "", ref, we.Data)
		}

	case "fuzzer.complete":
		if ref := compact(we.Data, &campaignFields{}); ref != nil {
			d.enqueue(TriggerFuzzerComplete, "", ref, we.Data)
		}
	}
}

// RunCompleted reports a finished automation run to the dispatcher.
//
// Called by Manager.noteLastRun rather than reached through the event bus, and that is
// the whole design of this trigger: a per-run broadcast would be a firehose an agent
// controls, which is the reason automation.script.state is the only automation event on
// the bus. In process, the event reaches the dispatcher and nothing else.
//
// Runs the operator started by hand count. An operator testing an automation should see
// what it chains to, and the alternative is a trigger that behaves differently in testing
// than when armed.
func (d *Dispatcher) RunCompleted(automationID string, run *Run) {
	if d == nil || run == nil || automationID == "" {
		return
	}
	if ref := RunRef(automationID, run); ref != nil {
		d.enqueue(TriggerAutomationCompleted, automationID, ref, ref)
	}
}

// enqueue adds a reference to every automation armed for that trigger whose conditions
// the event satisfies.
//
// Filtering here rather than at dispatch is what keeps a rejected event from consuming a
// slot in the coalescing buffer and inflating the dropped count an automation is told
// about. An automation watching for critical findings should not be told it missed
// informational ones.
//
// from names the automation that produced the event, and is empty for anything Joro
// produced. It exists for the one rule below.
//
// ref and payload are the same event seen two ways, and keeping them apart is what makes a
// condition on this event work at all. ref is what the script is handed, and its shape is the
// SDK's contract with every automation already written against it — a finding arrives nested
// under `finding`, a finished run reports what started it as `on`. payload is the producer's
// own broadcast, which trigger.Project reconciles against the vocabulary the operator wrote
// their condition in. Matching the script's payload directly is what used to happen, and it
// silently matched nothing: NewJSONSubject is a flat lookup, so `severity` found the wrapper
// rather than the finding inside it.
func (d *Dispatcher) enqueue(on, from string, ref json.RawMessage, payload any) {
	fields := trigger.Project(on, payload)
	if fields == nil {
		// Unreadable is not the same as empty. An empty projection satisfies a negated
		// condition, which would fire a trigger the operator wrote to exclude this.
		return
	}
	subject := trigger.NewMapSubject(fields)

	d.mu.Lock()
	for _, a := range d.armed {
		when, ok := a.find(on)
		if !ok {
			continue
		}
		// An automation never sees its own completion. Chaining exists so one automation
		// can react to another; an automation reacting to itself is a loop with no
		// condition that can stop it, since the event it fires on is the one its own run
		// produces. Cycles through a second automation are still possible and are what
		// the runaway breaker is for — this closes only the case no breaker should have
		// to catch.
		if from != "" && from == a.id {
			continue
		}
		if !when.Matches(subject) {
			continue
		}
		if len(a.pending[on]) >= pendingCap {
			// Drop the oldest: a stale event matters less than a fresh one, and the
			// count travels to the script so the loss is visible rather than silent.
			a.pending[on] = a.pending[on][1:]
			a.dropped[on]++
		}
		a.pending[on] = append(a.pending[on], ref)
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
		on      string
		payload json.RawMessage
		// batchMax is the highest capture sequence this batch actually contained, so a
		// watcher advances to exactly what it was shown rather than to an estimate.
		batchMax int
	}
	// One byte budget for the whole pass, shared by every automation, because the cost
	// this bounds is the dispatcher goroutine's and there is only one of those.
	budget := &scanBudget{left: maxScanBytes}
	clear(d.subjects)

	var jobs []job
	for _, a := range d.armed {
		if a.running {
			continue
		}
		// The interval paces runs, not scanning. Gating the scan on it too would leave a
		// selectively filtered automation examining fifty captures per interval while
		// traffic arrived faster, so it would fall behind and never catch up. Scanning
		// always runs; it advances the cursor over what the conditions rejected and
		// stops at the first match, which is then waiting when the interval elapses.
		on, payload, batchMax := d.nextBatchLocked(a, budget, now.Sub(a.lastRun) >= a.interval)
		if payload == nil {
			continue
		}
		a.running = true
		jobs = append(jobs, job{a: a, on: on, payload: payload, batchMax: batchMax})
	}
	d.mu.Unlock()

	for _, j := range jobs {
		go d.runOne(ctx, j.a, j.on, j.payload, j.batchMax)
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
func (d *Dispatcher) nextBatchLocked(a *armed, budget *scanBudget, mayRun bool) (string, json.RawMessage, int) {
	for _, t := range a.triggers {
		switch t.on {
		case TriggerRequestCaptured:
			if d.store == nil {
				continue
			}
			items, batchMax := d.scanTrafficLocked(a, t.when, budget)
			if len(items) == 0 || !mayRun {
				continue
			}
			dropped := a.takeDropped(t.on)
			if a.isCommand {
				dropped += len(items) - 1
				items = items[len(items)-1:]
			}
			return t.on, requestBatch(t.ref, items, dropped), batchMax

		default:
			refs := a.pending[t.on]
			if len(refs) == 0 || !mayRun {
				continue
			}
			n := min(len(refs), maxTriggerBatch)
			batch := refs[:n]
			a.pending[t.on] = refs[n:]
			dropped := a.takeDropped(t.on)
			if a.isCommand && len(batch) > 1 {
				dropped += len(batch) - 1
				batch = batch[len(batch)-1:]
			}
			return t.on, discreteBatch(t.on, t.ref, batch, dropped), 0
		}
	}
	return "", nil, 0
}

// scanBudget is one pass's allowance for reading captured bytes, shared across every
// armed automation.
type scanBudget struct{ left int }

func (b *scanBudget) spend(n int) bool {
	if b.left <= 0 {
		return false
	}
	b.left -= n
	return true
}

// scanTrafficLocked walks forward from the cursor and returns the captures this
// automation's conditions accept, plus the highest sequence it examined.
//
// It moves the cursor itself, which no other scan in this file does — see the rule at the
// bottom, which is what stops a filtered automation re-reading the same window forever.
//
// The returned batchMax is the highest sequence *examined*, not the highest delivered, so
// the run that follows advances past what it was shown and past what it was spared.
//
// Called with d.mu held.
func (d *Dispatcher) scanTrafficLocked(a *armed, when *trigger.Compiled, budget *scanBudget) ([]*proxy.CapturedRequest, int) {
	cursor := int(a.cursor)

	if when == nil {
		// Unfiltered: one read is the batch, exactly as this worked before conditions
		// existed, and nothing is parsed.
		items := d.store.SinceSeq(cursor, maxTriggerBatch)
		if len(items) == 0 {
			return nil, cursor
		}
		return items, items[len(items)-1].Seq
	}

	var (
		out      []*proxy.CapturedRequest
		examined = cursor
		// firstMatch is where the batch begins. Everything before it was examined and
		// rejected, and is what the cursor can safely be moved over.
		firstMatch = 0
	)
scan:
	for len(out) < maxTriggerBatch && examined-cursor < maxTriggerScan {
		items := d.store.SinceSeq(examined, maxTriggerBatch)
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			if !budget.spend(len(it.ReqRaw) + len(it.RespRaw)) {
				// Out of bytes for this pass. Stop where we are rather than skipping
				// ahead: an unexamined capture must not be counted as rejected.
				break scan
			}
			examined = it.Seq
			if when.Matches(d.subjectFor(it)) {
				if firstMatch == 0 {
					firstMatch = it.Seq
				}
				out = append(out, it)
				if len(out) >= maxTriggerBatch {
					break scan
				}
			}
		}
	}

	// Move the cursor over the rejected prefix, and no further.
	//
	// A rejected capture is resolved: this pass looked at it and decided, and nothing will
	// decide differently later, so re-reading it is pure waste. finish moves the cursor
	// only for a run that actually happened, so without this a filtered automation would
	// re-examine the same window on every 250ms tick — forever when nothing matches, and
	// until the interval elapses when something does.
	//
	// It stops at the first match rather than at everything examined, because the batch
	// beyond that point is not resolved yet. The run may be refused as busy, or fail, and
	// then the next pass has to be able to pick the same captures up.
	if to := firstMatch - 1; firstMatch > 0 && to > int(a.cursor) {
		a.cursor = int64(to)
	} else if firstMatch == 0 && examined > int(a.cursor) {
		a.cursor = int64(examined)
	}
	return out, examined
}

// subjectFor returns the condition subject for one capture, built at most once per pass
// however many automations are watching. Parsing a body is the expensive half of a
// condition and it does not become more expensive per subscriber.
func (d *Dispatcher) subjectFor(it *proxy.CapturedRequest) trigger.Subject {
	if s, ok := d.subjects[it.Seq]; ok {
		return s
	}
	s := trigger.NewRequestSubject(it)
	d.subjects[it.Seq] = s
	return s
}

func (a *armed) takeDropped(on string) int {
	n := a.dropped[on]
	delete(a.dropped, on)
	return n
}

// runOne executes one batch and settles the automation's state afterwards.
func (d *Dispatcher) runOne(ctx context.Context, a *armed, on string, payload json.RawMessage, batchMax int) {
	run, err := d.mgr.Invoke(ctx, InvokeRequest{
		ID:     a.id,
		Caller: AutomationPrincipal(a.id),
		// Invoke applies the automation's own host whitelist, since a trigger-fired run
		// has no launching token to inherit one from.
		Trigger:     on,
		TriggerData: payload,
	})
	if err != nil {
		// Busy is ordinary backpressure: leave the cursor unmoved so the next pass picks
		// the same traffic up. Discrete events were already consumed, which is the right
		// trade for something that has been coalesced anyway.
		if err != ErrBusy {
			log.Printf("[automation] %s: %v", a.id, err)
		}
		d.finish(a, nil, on, 0)
		return
	}
	d.finish(a, run, on, batchMax)
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
func (d *Dispatcher) finish(a *armed, run *Run, on string, batchMax int) {
	now := time.Now()

	head := 0
	if producedTraffic(a, run) && d.store != nil {
		head = d.store.LastSeq()
	}

	d.mu.Lock()
	a.running = false
	a.lastRun = now

	if run != nil && on == TriggerRequestCaptured {
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
	// The trigger store gets its own counter, and both are checked: editing a trigger
	// changes what an automation fires on without touching the automation, so watching
	// only the package revision would leave every user of that trigger running the
	// version compiled before the edit.
	var trigRev uint64
	if d.triggers != nil {
		trigRev = d.triggers.Revision()
	}

	d.mu.Lock()
	if d.loaded && rev == d.knownRev && trigRev == d.knownTrig {
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
		cur.triggers = d.compileArmed(a.Manifest.ID, triggers)
		cur.interval = effectiveInterval(a)
		cur.isCommand = a.Manifest.IsCommand()
	}

	for id, a := range d.armed {
		if _, still := seen[id]; !still && !a.running {
			delete(d.armed, id)
		}
	}

	d.knownRev = rev
	d.knownTrig = trigRev
	d.loaded = true
}

// compileArmed resolves an automation's trigger references and compiles each one, once
// per edit rather than once per candidate.
//
// A reference that resolves to nothing, or to a trigger this build cannot read, becomes a
// compiled trigger that refuses every event — never one with no filter. That polarity is
// the whole point: a trigger exists to narrow when an automation runs, so "the narrowing
// is missing" must not mean "run for everything". An operator who deleted a trigger out
// from under an automation gets silence and a log line, not a script suddenly firing on
// every request in the engagement.
//
// The event is taken from the resolved trigger rather than from the reference, which is
// what lets a custom trigger sit in the manifest wherever its event would.
func (d *Dispatcher) compileArmed(id string, refs []TriggerRef) []armedTrigger {
	out := make([]armedTrigger, 0, len(refs))
	for _, ref := range refs {
		name := string(ref)

		def, err := d.resolve(name)
		if err != nil {
			d.report(id, name, "it does not exist")
			out = append(out, armedTrigger{ref: name, when: trigger.Poison("no such trigger")})
			continue
		}
		when := trigger.Compile(&def)
		d.report(id, name, when.Reason)
		out = append(out, armedTrigger{ref: name, on: def.On, when: when})
	}
	return out
}

// report logs a trigger's problem the first time it appears, and logs its recovery once
// when it goes away. Called with d.mu held.
func (d *Dispatcher) report(id, ref, reason string) {
	key := id + "\x00" + ref
	if d.reported[key] == reason {
		return
	}
	switch {
	case reason == "":
		log.Printf("[automation] %s: trigger %q is readable again", id, ref)
		delete(d.reported, key)
	default:
		log.Printf("[automation] %s: trigger %q will not fire, %s", id, ref, reason)
		d.reported[key] = reason
	}
}

// resolve looks a reference up, falling back to the built-in events when no trigger store
// is wired. Without one only the built-ins exist, which is a Joro that has never had a
// custom trigger rather than an error.
func (d *Dispatcher) resolve(ref string) (trigger.Trigger, error) {
	if d.triggers != nil {
		return d.triggers.Resolve(ref)
	}
	if !trigger.IsBuiltin(ref) {
		return trigger.Trigger{}, trigger.ErrNotFound
	}
	for _, t := range trigger.BuiltinTriggers() {
		if t.ID == ref {
			return t, nil
		}
	}
	return trigger.Trigger{}, trigger.ErrNotFound
}

// WatchTriggers wires the custom trigger store. Called once at startup, before Run.
func (d *Dispatcher) WatchTriggers(store *trigger.Store) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.triggers = store
	d.loaded = false
	d.mu.Unlock()
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

// The run is recorded and dispatched under the *event*, not under the reference that
// selected it, because everything downstream keys on the event: the command placeholder
// table, the lens principal, the batching and the cursor rule all ask what kind of thing
// happened. The reference rides in the payload as triggerId instead, so a script watching
// two custom triggers on one event can still tell which one woke it — information that
// would otherwise be lost the moment an operator built a second trigger on request.captured.

func requestBatch(ref string, items []*proxy.CapturedRequest, dropped int) json.RawMessage {
	refs := make([]requestRef, 0, len(items))
	for _, it := range items {
		refs = append(refs, requestRef{
			Seq: it.Seq, Method: it.Method, Host: it.Host,
			URL: it.URL, Status: it.StatusCode, ContentType: it.ContentType,
		})
	}
	b, err := json.Marshal(map[string]any{
		"requests": refs, "dropped": dropped, "triggerId": ref,
	})
	if err != nil {
		return nil
	}
	return b
}

func discreteBatch(on, ref string, refs []json.RawMessage, dropped int) json.RawMessage {
	key := "events"
	switch on {
	case TriggerDetectFinding:
		key = "findings"
	case TriggerFuzzerComplete:
		key = "campaigns"
	case TriggerAutomationCompleted:
		key = "runs"
	}
	b, err := json.Marshal(map[string]any{key: refs, "dropped": dropped, "triggerId": ref})
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
//
// It is also the whole vocabulary a condition on this trigger can address, which is why
// it carries more than the run itself needs: a field absent here is a filter an operator
// cannot write. Adding one means adding it to triggerFields too.
type findingFields struct {
	ID         string `json:"id"`
	Host       string `json:"host,omitempty"`
	URL        string `json:"url,omitempty"`
	Name       string `json:"name,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Category   string `json:"category,omitempty"`
	RuleID     string `json:"ruleId,omitempty"`
}

// runFields is what an automation.completed event carries, and the vocabulary a condition
// trigger it can address.
//
// References and counts, no logs and no captured bytes — the same rule requestRef follows.
// Value is the exception and is capped: a chain whose second step reacts to what the first
// returned is the point of chaining, and a return value is the automation's own output
// rather than something it was shown.
type runFields struct {
	AutomationID string `json:"automationId"`
	RunID        string `json:"runId"`
	Version      string `json:"version,omitempty"`
	Trigger      string `json:"on,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	Reason       string `json:"reason,omitempty"`
	DurationMs   int64  `json:"durationMs,omitempty"`
	Calls        int    `json:"calls,omitempty"`
	SendCalls    int    `json:"sendCalls,omitempty"`
	ExitCode     *int   `json:"exitCode,omitempty"`
	Value        string `json:"value,omitempty"`
}

// maxTriggerValueBytes caps the return value carried into a chained run. Large enough for
// a status string or a small object, small enough that a chain cannot become a way to
// move a body between automations.
const maxTriggerValueBytes = 4 << 10

// RunRef projects a finished run into the reference its successors see.
//
// Exported because automation.completed never reaches Joro's bus, so anything else that wants
// to react to a finished run is registered through Manager.WatchRuns and has to project the
// Run itself. One projection rather than one per watcher: the field names here are what
// trigger.Project reconciles against the condition vocabulary, and a second hand-written copy
// is how a condition comes to fire for one watcher and not another.
func RunRef(automationID string, run *Run) json.RawMessage {
	f := runFields{
		AutomationID: automationID,
		RunID:        run.ID,
		Trigger:      run.Trigger,
		Outcome:      run.Result.Outcome,
		Reason:       run.Result.Reason,
		DurationMs:   run.DurationMs,
		Calls:        run.Result.Calls,
		SendCalls:    run.Result.SendCalls,
	}
	if run.Result.Outcome == "" {
		// A Result the host has not stamped yet still has its Reason, and a condition on
		// outcome should not silently match nothing because of where it was read.
		f.Outcome = jsruntime.OutcomeFor(run.Result.Reason)
	}
	if v := run.Result.Value; len(v) > 0 {
		f.Value = string(v)
		if len(f.Value) > maxTriggerValueBytes {
			f.Value = f.Value[:maxTriggerValueBytes]
		}
		// A command's exit status lives inside its value rather than on the Result, since
		// a command consumes none of the runtime's counters. Pulled out here so a chain
		// can branch on it without the successor parsing stdout.
		var cv struct {
			ExitCode *int `json:"exitCode"`
		}
		if json.Unmarshal(v, &cv) == nil && cv.ExitCode != nil {
			f.ExitCode = cv.ExitCode
		}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	return b
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
