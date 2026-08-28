package webhook

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/trigger"
)

// What a matched event carries into a delivery.
//
// The projection is derived from the field catalog rather than written out as a struct per
// event, and that is the point rather than an economy. internal/trigger's catalog is already
// the single statement of what each event carries — it is what the condition editor offers
// and what a template may name — so deriving the payload from it means the three can never
// disagree. A field added to the catalog appears in conditions, in templates and in the
// envelope with nothing here to edit.
//
// Bytes fields are the one exclusion, for the reason knownTokens gives: they exist so a
// condition can search a body, and a notification is not where a megabyte belongs.

// Event is one thing that happened, projected down to what a delivery may say about it.
type Event struct {
	// On is the event kind. Ref is the trigger reference that matched, which is what
	// distinguishes two triggers watching one event.
	On  string `json:"-"`
	Ref string `json:"-"`

	At time.Time `json:"-"`

	// Fields is the catalog projection: every non-bytes field the event actually carried.
	Fields map[string]any `json:"-"`

	// Summary is Joro's one-liner, computed once here so the presets and the envelope agree.
	Summary string `json:"-"`
}

// newEvent projects one matched event.
func newEvent(on, ref string, s trigger.Subject) Event {
	fields := map[string]any{}
	for _, spec := range trigger.Fields()[on] {
		if spec.Kind == trigger.KindBytes {
			continue
		}
		v := s.Value(spec.Name)
		if !v.Ok {
			continue
		}
		switch {
		case v.IsNum:
			fields[spec.Name] = v.Num
		case v.Raw != nil:
			fields[spec.Name] = clip(string(v.Raw))
		default:
			fields[spec.Name] = clip(v.Text)
		}
	}
	e := Event{On: on, Ref: ref, At: time.Now(), Fields: fields}
	e.Summary = summarize(on, fields)
	return e
}

// subject reads the projection back through the same interface a condition uses, so a
// template resolving {{host}} and a condition testing host read the same value.
func (e Event) subject() trigger.Subject {
	raw, err := json.Marshal(e.Fields)
	if err != nil {
		return trigger.NewJSONSubject(nil)
	}
	return trigger.NewJSONSubject(raw)
}

// summarize writes the one-liner a notification leads with.
//
// Per-event rather than generic, because the whole value of a webhook is that a person reads
// one line in a chat client and knows whether to look. A generic key=value dump would be
// technically complete and useless for that.
func summarize(on string, f map[string]any) string {
	switch on {
	case trigger.EventDetectFinding:
		s := fmt.Sprintf("%s finding: %s", or(str(f["severity"]), "unrated"),
			or(str(f["name"]), "unnamed"))
		if host := str(f["host"]); host != "" {
			s += " on " + host
		}
		// Read through both forms. A projection carries the producer's own bool, and a
		// subject folds it to the word a KindBool condition compares against — so which one
		// arrives here depends on which path built the event, and a summary that quietly
		// stopped saying "already reported" would be the least visible way to notice.
		if isFalse(f["isNew"]) {
			s += " (already reported)"
		}
		return s

	case trigger.EventRequestCaptured:
		s := strings.TrimSpace(str(f["method"]) + " " + str(f["url"]))
		if code := num(f["status"]); code > 0 {
			s += fmt.Sprintf(" → %d", code)
		}
		return s

	case trigger.EventFuzzerComplete:
		s := fmt.Sprintf("fuzzing campaign %s %s", or(str(f["campaignId"]), "?"),
			or(str(f["status"]), "finished"))
		if n := num(f["completed"]); n > 0 {
			s += fmt.Sprintf(": %d requests", n)
		}
		if n := num(f["errors"]); n > 0 {
			s += fmt.Sprintf(", %d errors", n)
		}
		return s

	case trigger.EventAutomationComplete:
		return fmt.Sprintf("automation %s finished: %s", or(str(f["automationId"]), "?"),
			or(str(f["reason"]), or(str(f["outcome"]), "done")))
	}
	return on
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// isFalse reports a present, false-valued field in either form.
func isFalse(v any) bool {
	switch t := v.(type) {
	case bool:
		return !t
	case string:
		return t == "false"
	}
	return false
}

func num(v any) int64 {
	n, _ := v.(float64)
	return int64(n)
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ---- bus payload projection ----

// flattenBusEvent turns one broadcast payload into the field map the catalog describes, or
// nil when this build cannot read it.
//
// The reconciliation itself is trigger.Project's, and deliberately not repeated here: the
// automation dispatcher matches the same events against the same vocabulary, and a webhook
// that fired where an automation did not — or the reverse — would be the one difference an
// operator has no way to see. What is left here is the one judgement that is this package's
// own.
func flattenBusEvent(on string, data any) map[string]any {
	fields := trigger.Project(on, data)
	if fields == nil {
		return nil
	}
	// A finding an agent reported is not an engagement event. The reasoning is
	// jsautomation's and applies unchanged in a different currency: findings.create is
	// non-privileged and its host is a free string, so treating its broadcast as a trigger
	// would let any token holding it push arbitrary text into the operator's team channel.
	if on == trigger.EventDetectFinding && str(fields["ruleId"]) == agentReportedRuleID {
		return nil
	}
	return fields
}

// agentReportedRuleID mirrors capreg's agentFindingRuleID, the reserved rule under which
// findings.create files an agent's report. Duplicated rather than imported for the reason
// jsautomation duplicates it: capreg imports this package, so the reverse direction would be
// a cycle.
const agentReportedRuleID = "agent-reported"
