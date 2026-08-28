package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/trigger"
)

// Firing a webhook from an automation.
//
// This is the half a sandboxed run can reach, and its whole safety argument is that the run
// chooses *which* of the operator's endpoints, never *where*. The id is the only address; the
// URL, the headers and the secrets are not arguments here, are not in the result, and are not
// in the MCP tool schema. AllowAutomations is the operator's tick, default off, and it is what
// makes a webhook reachable at all — the same shape as an operator arming a command
// automation, where the authority is the arming rather than any grant.
//
// The payload is bounded and lands in fixed slots. A template's shape is still the operator's;
// {{MESSAGE}} is the one place a script writes. That is invariant two applied to the fire path:
// the body's shape is fixed before any agent value reaches it.

const (
	// MaxMessageLen bounds the one-line message a script supplies. Long enough for a real
	// finding summary, short enough that a notification channel is not a file transfer.
	MaxMessageLen = 2 << 10

	// MaxDataBytes bounds the structured payload an envelope carries. Ignored by the presets
	// and by templates, which have {{MESSAGE}} instead.
	MaxDataBytes = 8 << 10

	// firesPerMinute bounds how often one principal may fire.
	//
	// It has to live here rather than in the run's budget: webhook.fire declares
	// SendsTraffic false — scope does not describe an operator's notification endpoint, so
	// guarding it there would deny every call rather than bound one — and a run's send
	// budget is derived from exactly that flag. Without this a loop is a notification flood
	// with nothing counting it.
	firesPerMinute = 10
)

// FireResult is what a script is told about its delivery.
type FireResult struct {
	Webhook    string `json:"webhook"`
	Status     int    `json:"status"`
	DurationMs int64  `json:"durationMs"`
}

// Listed is one webhook as a script may see it. No URL, no headers, no secrets: knowing where
// a notification goes is not something a run needs in order to send one, and it is the half an
// exfiltration would want.
type Listed struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// List returns the webhooks a run may fire, sorted by name.
//
// Only the ones the operator opted in: a run has no reason to know about an endpoint it cannot
// reach, and listing one would invite a script to report it as unavailable rather than simply
// not existing.
func (d *Deliverer) List() []Listed {
	out := []Listed{}
	for _, w := range d.store.List() {
		if !w.AllowAutomations {
			continue
		}
		out = append(out, Listed{
			ID: w.ID, Name: w.Name, Description: w.Description,
			Enabled: w.Enabled && !w.Paused && w.Problem == "",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Fire sends one delivery on behalf of a run.
//
// Synchronous, unlike an event-driven delivery, and deliberately so: a script that notified a
// channel should be able to say whether it landed, and the alternative is a fire-and-forget
// call whose only failure signal is the operator noticing nothing arrived. It is bounded by
// the webhook's own timeout and does not retry — a retry loop inside a capability call is a
// run's budget being spent on waiting.
func (d *Deliverer) Fire(ctx context.Context, principal, id, message string, data json.RawMessage) (FireResult, error) {
	if d == nil || d.store == nil {
		return FireResult{}, fmt.Errorf("webhooks are unavailable on this instance")
	}
	if len(message) > MaxMessageLen {
		return FireResult{}, fmt.Errorf("the message is %d bytes, over the %d limit",
			len(message), MaxMessageLen)
	}
	if len(data) > MaxDataBytes {
		return FireResult{}, fmt.Errorf("data is %d bytes, over the %d limit",
			len(data), MaxDataBytes)
	}

	w, err := d.store.Get(id)
	if err != nil {
		// Existence is not disclosed separately from permission: a run that could tell a
		// webhook it may not fire from one that does not exist could enumerate the
		// operator's notification endpoints one guess at a time.
		return FireResult{}, fmt.Errorf("no webhook %q is available to automations", id)
	}
	switch {
	case !w.AllowAutomations:
		return FireResult{}, fmt.Errorf("no webhook %q is available to automations", id)
	case w.Problem != "":
		return FireResult{}, fmt.Errorf("webhook %q will not deliver: %s", id, w.Problem)
	case !w.Enabled:
		return FireResult{}, fmt.Errorf("webhook %q is switched off", id)
	case w.Paused:
		return FireResult{}, fmt.Errorf("webhook %q is paused: %s", id, w.PausedReason)
	}
	if !d.fires.allow(principal) {
		return FireResult{}, fmt.Errorf("this run has fired %d webhooks in the last minute, "+
			"which is the limit", firesPerMinute)
	}

	ev := Event{
		On:      "automation.fire",
		Ref:     principal,
		At:      time.Now(),
		Fields:  map[string]any{},
		Summary: message,
	}
	j := job{webhook: w, events: []Event{ev}}
	if w.Format == FormatTemplate {
		// Compiled here rather than taken from the dispatcher's cache: a webhook may name no
		// trigger at all when it exists only for scripts, in which case it is never armed.
		events, err := d.store.eventsFor(w.Triggers)
		if err != nil {
			return FireResult{}, err
		}
		tpl, err := ParseTemplate(w.Template, events)
		if err != nil {
			return FireResult{}, err
		}
		j.tpl = tpl
	}

	body, err := d.renderFire(j, message, data)
	if err != nil {
		return FireResult{}, err
	}

	start := time.Now()
	deliveryID := newDeliveryID()
	client := d.client(w.InsecureTLS)
	// See deliver: the transport is per-call so SOCKS stays live, which leaves its idle
	// pool with no owner unless it is closed here.
	defer client.CloseIdleConnections()

	status, sendErr := d.send(ctx, &client, time.Duration(w.TimeoutMs)*time.Millisecond,
		j, deliveryID, body)

	rec := Delivery{
		ID: deliveryID, At: start, Event: "automation.fire", Trigger: principal,
		Events: 1, Attempts: 1, Status: status,
	}
	if sendErr != nil {
		rec.Error = sendErr.Error()
	}
	d.record(w.ID, rec, start)

	if sendErr != nil {
		return FireResult{}, sendErr
	}
	return FireResult{Webhook: w.ID, Status: status,
		DurationMs: time.Since(start).Milliseconds()}, nil
}

// renderFire builds the body for a fired delivery. The message fills {{MESSAGE}} and stands in
// for {{SUMMARY}}, so the presets say something useful with no template at all.
func (d *Deliverer) renderFire(j job, message string, data json.RawMessage) ([]byte, error) {
	c := renderContext{
		Event:    "automation.fire",
		Trigger:  j.events[0].Ref,
		Webhook:  j.webhook.Name,
		Instance: d.instance,
		At:       j.events[0].At,
		Summary:  message,
		Message:  message,
	}
	ref := map[string]any{"event": "automation.fire", "summary": message}
	if len(data) > 0 {
		// Carried as raw JSON so the operator's receiver sees exactly what the script sent.
		// Shape-safe regardless: it is a value in a document Joro builds, so Marshal escapes
		// it and it cannot reach out of its own key.
		ref["data"] = data
	}
	return renderBody(&j.webhook, j.tpl, c, []map[string]any{ref}, 0)
}

// ---- test deliveries ----

// TestResult is what the editor shows for a dry run: the exact bytes sent and what came back.
type TestResult struct {
	Body       string `json:"body"`
	Status     int    `json:"status"`
	DurationMs int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// Test renders a webhook against a sample of the first event it watches and delivers it.
//
// The sample is built from the field catalog rather than replayed from captured traffic, so a
// test says something on a fresh Joro with nothing in History and on a webhook watching an
// event that has no corpus at all — a finished campaign, a finished run. What it verifies is
// the half an operator gets wrong: the rendered bytes, the headers, the signature, and whether
// the endpoint accepts them.
func (d *Deliverer) Test(ctx context.Context, id string) (TestResult, error) {
	w, err := d.store.Get(id)
	if err != nil {
		return TestResult{}, err
	}
	if w.Problem != "" {
		return TestResult{}, fmt.Errorf("%s", w.Problem)
	}

	events, err := d.store.eventsFor(w.Triggers)
	if err != nil {
		return TestResult{}, err
	}

	// A webhook that names no trigger exists only for scripts to fire, so there is no event
	// to sample. It is tested as the thing it is: a message, filling the slot a script would.
	if len(events) == 0 {
		j := job{webhook: w, events: []Event{{
			On: "automation.fire", Ref: "test", At: time.Now(), Fields: map[string]any{},
		}}}
		if w.Format == FormatTemplate {
			tpl, err := ParseTemplate(w.Template, nil)
			if err != nil {
				return TestResult{}, err
			}
			j.tpl = tpl
		}
		body, err := d.renderFire(j, "Test delivery from Joro", nil)
		if err != nil {
			return TestResult{}, err
		}
		return d.attempt(ctx, w, j, body, "test")
	}

	on := events[0]
	j := job{webhook: w, events: []Event{sampleEvent(on, w.Triggers[0])}}
	if w.Format == FormatTemplate {
		tpl, err := ParseTemplate(w.Template, events)
		if err != nil {
			return TestResult{}, err
		}
		j.tpl = tpl
	}

	body, err := d.render(j)
	if err != nil {
		return TestResult{}, err
	}
	return d.attempt(ctx, w, j, body, j.events[0].Ref)
}

// attempt sends one test delivery and records it. A single attempt, not the retry loop: a
// test is a question about the endpoint, and answering it three times over a backoff would
// make the operator wait to be told the same thing.
func (d *Deliverer) attempt(ctx context.Context, w Webhook, j job, body []byte, ref string) (TestResult, error) {
	start := time.Now()
	deliveryID := newDeliveryID()
	client := d.client(w.InsecureTLS)
	defer client.CloseIdleConnections()

	status, sendErr := d.send(ctx, &client, time.Duration(w.TimeoutMs)*time.Millisecond,
		j, deliveryID, body)

	res := TestResult{Body: string(body), Status: status,
		DurationMs: time.Since(start).Milliseconds()}
	if sendErr != nil {
		res.Error = sendErr.Error()
	}

	rec := Delivery{
		ID: deliveryID, At: start, Event: "test", Trigger: ref,
		Events: 1, Attempts: 1, Status: status, Error: res.Error,
	}
	d.record(w.ID, rec, start)
	return res, nil
}

// sampleEvent fabricates one event of a kind, filling every field the catalog describes.
//
// Enum fields take their first declared value, so a sample says "critical" rather than
// guessing at the spelling — the same reason FieldSpec.Values exists for the condition editor.
func sampleEvent(on, ref string) Event {
	fields := map[string]any{}
	for _, spec := range trigger.Fields()[on] {
		if spec.Kind == trigger.KindBytes {
			continue
		}
		switch {
		case len(spec.Values) > 0:
			fields[spec.Name] = spec.Values[0]
		case spec.Kind == trigger.KindNumber, spec.Kind == trigger.KindStatus:
			fields[spec.Name] = float64(200)
		case spec.Kind == trigger.KindBool:
			fields[spec.Name] = "true"
		default:
			fields[spec.Name] = "sample-" + spec.Name
		}
	}
	// Two fields worth a realistic value, because they are the ones a person reads.
	if _, ok := fields["host"]; ok {
		fields["host"] = "example.com"
	}
	if _, ok := fields["url"]; ok {
		fields["url"] = "https://example.com/sample"
	}
	e := Event{On: on, Ref: ref, At: time.Now(), Fields: fields}
	e.Summary = "Test delivery from Joro — " + summarize(on, fields)
	return e
}

// ---- per-principal fire limiting ----

// fireLimiter is a one-minute sliding window per principal. A run's principal is synthetic and
// per-run, so this is a per-run budget; a long-lived token's is per token, which is what an
// agent firing on its own schedule should be held to.
type fireLimiter struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

func newFireLimiter() *fireLimiter {
	return &fireLimiter{seen: map[string][]time.Time{}}
}

func (l *fireLimiter) allow(principal string) bool {
	now := time.Now()
	cut := now.Add(-time.Minute)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Sweep every principal, not only this one: run principals are synthetic and never seen
	// again, so keeping only the current key would leak an entry per run.
	for k, times := range l.seen {
		i := 0
		for i < len(times) && times[i].Before(cut) {
			i++
		}
		if i == len(times) {
			delete(l.seen, k)
			continue
		}
		l.seen[k] = times[i:]
	}

	if len(l.seen[principal]) >= firesPerMinute {
		return false
	}
	l.seen[principal] = append(l.seen[principal], now)
	return true
}
