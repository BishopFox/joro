package webhook

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/trigger"
)

// The webhook dispatcher: one goroutine that decides which events are worth a delivery.
//
// A sibling of jsautomation.Dispatcher rather than a reuse of it, and the difference between
// them is the whole reason this is only a hundred lines. That one is welded to *Manager at
// both seams, and its batching, its cursor over the capture store and its runaway breaker all
// exist to amortise spawning a worker process. None of that applies here.
//
// In particular there is no cursor, and that is deliberate rather than a shortcut. An
// automation run is expensive and must not miss traffic, so it needs an authoritative
// sequence over the capture store and treats the bus as a doorbell. A webhook is a
// *notification*: best-effort with a visible drop count is the correct contract, which is
// exactly what Hub.Subscribe's documented non-blocking send already provides. The bus payload
// for request.captured is the whole *proxy.CapturedRequest — headers and body included — so a
// condition on a response body evaluates at full fidelity straight off the channel, with no
// second read of the store.
//
// The capture pointer is shared with the ring buffer and is never retained past matching:
// newEvent projects what a delivery may say, and the queue holds only that.

// reloadInterval is how often the armed set is checked against the stores. Slower than the
// automation dispatcher's 250ms because nothing here is waiting on it — an edit takes effect
// within a second, and a webhook is not a control an operator toggles mid-request.
const reloadInterval = time.Second

// Dispatcher watches Joro's events and hands matches to the deliverer.
type Dispatcher struct {
	store   *Store
	deliver *Deliverer

	mu       sync.Mutex
	armed    map[string]*armed
	knownRev uint64
	knownTrg uint64
	loaded   bool

	// watchesTraffic is whether any armed webhook watches request.captured, checked before
	// a capture is touched at all. Traffic is the one high-volume event, and this is what
	// keeps a Joro whose webhooks all watch findings from parsing a URL per request.
	watchesTraffic bool

	// reported remembers the last problem logged per webhook, so a broken trigger is
	// reported when it breaks rather than on every reload.
	reported map[string]string
}

// armed is one webhook, compiled.
type armed struct {
	hook     Webhook
	tpl      *Template
	triggers []armedTrigger
}

// armedTrigger is one live subscription: the reference the webhook names, the event it
// resolved to, and the compiled filter.
//
// ref and on differ whenever a custom trigger is involved, and both are needed — the delivery
// reports the reference so two triggers on one event stay distinguishable, while matching keys
// on the event.
type armedTrigger struct {
	ref  string
	on   string
	when *trigger.Compiled
}

// NewDispatcher returns a dispatcher and wires the deliverer to read its compiled set.
func NewDispatcher(store *Store, deliver *Deliverer) *Dispatcher {
	d := &Dispatcher{
		store:    store,
		deliver:  deliver,
		armed:    map[string]*armed{},
		reported: map[string]string{},
	}
	if deliver != nil {
		deliver.armed = d.armedFor
	}
	return d
}

// armedFor returns the compiled webhook the deliverer should render with, or false when it is
// no longer armed.
func (d *Dispatcher) armedFor(id string) (Webhook, *Template, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.armed[id]
	if !ok {
		return Webhook{}, nil, false
	}
	return a.hook, a.tpl, true
}

// Run is the dispatcher loop. events is a subscription to Joro's event bus; it is read here
// rather than in its own goroutine so that observing an event and deciding on it are
// serialized, and the armed set needs no lock against a second path.
func (d *Dispatcher) Run(ctx context.Context, events <-chan any) {
	if d == nil || d.store == nil {
		return
	}
	d.reload()

	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			d.Observe(ev)
		case <-ticker.C:
			d.reload()
		}
	}
}

// Observe classifies one event and enqueues a delivery for every webhook whose conditions it
// satisfies.
//
// Exported because automation.completed never reaches the bus — a per-run broadcast would be
// a firehose an agent controls, so jsautomation reports a finished run in process. The API
// wires that path to this method, which is why the vocabulary here is the catalog's rather
// than any producer's own struct.
func (d *Dispatcher) Observe(ev any) {
	we, ok := ev.(event.WSEvent)
	if !ok {
		// Some producers send a bare map; all of those are team.* events, which no trigger
		// watches.
		return
	}

	switch we.Type {
	case trigger.EventRequestCaptured:
		d.mu.Lock()
		watching := d.watchesTraffic
		d.mu.Unlock()
		if !watching {
			return
		}
		capture, ok := we.Data.(*proxy.CapturedRequest)
		if !ok {
			return
		}
		// One subject for the event, shared by every webhook watching it: parsing a body is
		// the expensive half of a condition and does not get more expensive per subscriber.
		d.match(we.Type, trigger.NewRequestSubject(capture))

	case trigger.EventDetectFinding, trigger.EventFuzzerComplete, trigger.EventAutomationComplete:
		fields := flattenBusEvent(we.Type, we.Data)
		if fields == nil {
			return
		}
		d.match(we.Type, trigger.NewMapSubject(fields))
	}
}

// match enqueues one event for every armed webhook that accepts it.
//
// Filtering here rather than at delivery is what keeps a rejected event from consuming a slot
// in the queue and inflating the dropped count a receiver is told about: a webhook watching
// for critical findings should not report that it missed informational ones.
func (d *Dispatcher) match(on string, s trigger.Subject) {
	d.mu.Lock()
	type hit struct{ id, ref string }
	var hits []hit
	for id, a := range d.armed {
		for _, t := range a.triggers {
			if t.on != on {
				continue
			}
			if !t.when.Matches(s) {
				continue
			}
			hits = append(hits, hit{id: id, ref: t.ref})
			// One delivery per webhook per event, even when two of its triggers accept it.
			break
		}
	}
	d.mu.Unlock()

	if len(hits) == 0 {
		return
	}
	// Projected once, after at least one webhook has accepted it, so an event nothing wants
	// costs a condition evaluation and nothing else.
	ev := newEvent(on, "", s)
	for _, h := range hits {
		ev.Ref = h.ref
		d.deliver.Enqueue(h.id, ev)
	}
}

// reload syncs the armed set with the store, but only when something changed — otherwise every
// tick would recompile every trigger and reparse every template.
func (d *Dispatcher) reload() {
	rev := d.store.Revision()
	trg := d.store.TriggerRevision()

	d.mu.Lock()
	if d.loaded && rev == d.knownRev && trg == d.knownTrg {
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()

	// Both counters are checked: editing a trigger changes what a webhook fires on without
	// touching the webhook, so watching only the webhook revision would leave every user of
	// that trigger matching against the version compiled before the edit.
	list := d.store.List()

	next := make(map[string]*armed, len(list))
	traffic := false
	for _, w := range list {
		if !w.Enabled || w.Paused || w.Problem != "" {
			continue
		}
		a := &armed{hook: w, triggers: d.compile(w)}
		if w.Format == FormatTemplate {
			events := make([]string, 0, len(a.triggers))
			for _, t := range a.triggers {
				events = append(events, t.on)
			}
			tpl, err := ParseTemplate(w.Template, events)
			if err != nil {
				// Refused rather than delivered without substitution. A notification whose
				// body still reads "{{severity}}" is worse than one that did not arrive,
				// because it looks like it worked.
				d.report(w.ID, err.Error())
				continue
			}
			a.tpl = tpl
		}
		next[w.ID] = a
		for _, t := range a.triggers {
			if t.on == trigger.EventRequestCaptured {
				traffic = true
			}
		}
	}

	d.mu.Lock()
	// Collected rather than forgotten in place. Locks between the dispatcher and the
	// deliverer are only ever taken deliverer-first — Deliverer.pump holds its own while it
	// reads armedFor — so taking the deliverer's lock while holding this one is the
	// inversion that would deadlock the two goroutines against each other.
	var gone []string
	for id := range d.armed {
		if _, still := next[id]; !still {
			gone = append(gone, id)
		}
	}
	d.armed = next
	d.watchesTraffic = traffic
	d.knownRev = rev
	d.knownTrg = trg
	d.loaded = true
	d.mu.Unlock()

	for _, id := range gone {
		d.deliver.Forget(id)
	}
}

// compile resolves a webhook's trigger references and compiles each one, once per edit rather
// than once per event.
//
// A reference that resolves to nothing, or to a trigger this build cannot read, becomes a
// filter that refuses every event — never one with no filter. The polarity is internal/trigger's
// and it reads backwards if inferred: a trigger exists to narrow when something happens, so a
// narrowing that cannot be read must not mean "deliver everything". An operator who deleted a
// trigger out from under a webhook gets silence and a log line, not their notification channel
// filled with every request in the engagement.
func (d *Dispatcher) compile(w Webhook) []armedTrigger {
	out := make([]armedTrigger, 0, len(w.Triggers))
	for _, ref := range w.Triggers {
		def, err := d.store.resolve(ref)
		if err != nil {
			d.report(w.ID, "trigger "+ref+" does not exist")
			out = append(out, armedTrigger{ref: ref, when: trigger.Poison("no such trigger")})
			continue
		}
		c := trigger.Compile(&def)
		d.report(w.ID, c.Reason)
		out = append(out, armedTrigger{ref: ref, on: def.On, when: c})
	}
	return out
}

// report logs a webhook's problem the first time it appears, and its recovery once when it
// goes away. Reloads are frequent and unrelated to the problem, so without this a single
// unreadable trigger would fill the log at the reload rate.
func (d *Dispatcher) report(id, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reported[id] == reason {
		return
	}
	if reason == "" {
		log.Printf("[webhook] %s is deliverable again", id)
		delete(d.reported, id)
		return
	}
	log.Printf("[webhook] %s will not deliver: %s", id, reason)
	d.reported[id] = reason
}
