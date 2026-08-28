package trigger

import (
	"encoding/json"
	"strconv"
)

// Projecting a broadcast payload into the condition vocabulary.
//
// The catalog in catalog.go is what an operator writes against: it is what the condition
// editor offers, and naming a field it does not list is what Compile refuses. A producer,
// meanwhile, sends whatever shape its own type has — detect broadcasts a finding wrapped in
// an envelope carrying isNew, and calls the rule's name ruleName. The two have to be
// reconciled somewhere, and this is that place.
//
// One place rather than one per consumer, and that is the point rather than tidiness. Two
// things now match events against this vocabulary — the automation dispatcher and the webhook
// dispatcher — and a reconciliation done twice is one that can be done differently twice, so
// a condition would fire for one and not the other. The tables below are small, and being
// small is not the reason they are here; being singular is.
//
// This deliberately does not touch what a *script* is handed. A payload's shape is the SDK's
// contract with the automations already written against it, and it is free to differ from the
// vocabulary a condition is written in. jsautomation projects that separately.

// payloadWrapper names the key a producer nests its object under, for the events broadcast
// inside an envelope. The outer object's own fields survive the unwrapping — detect.finding
// carries isNew out there, and an operator has no reason to know that.
var payloadWrapper = map[string]string{
	EventDetectFinding: "finding",
}

// payloadKeys maps a catalog field to the key its producer actually sends, for the cases
// where the two differ.
//
// The catalog is the side that stays fixed, because it is the side an operator typed. Both
// entries below are a producer's own struct tag showing through: detect.FindingSummary calls
// the rule's name ruleName, and a finished run reports what started it as on.
var payloadKeys = map[string]map[string]string{
	EventDetectFinding:      {"name": "ruleName"},
	EventAutomationComplete: {"trigger": "on"},
}

// Project turns one broadcast payload into a flat map keyed by the catalog's own field names.
//
// Returns nil for a payload this build cannot read, which callers must treat as "no event"
// rather than as an empty one — an empty projection would satisfy an `exists` negation and
// fire a trigger the operator wrote to exclude it.
//
// Fields outside the catalog are dropped. They are things an operator has no way to name, so
// carrying them would put values in a webhook body that no condition could filter on.
//
// Values keep their JSON types: a number stays a number and a bool stays a bool, so a
// consumer rendering this as JSON produces the shape a receiver expects. NewMapSubject is
// what folds them into the string comparisons a condition makes.
func Project(on string, data any) map[string]any {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var outer map[string]any
	if json.Unmarshal(raw, &outer) != nil || outer == nil {
		return nil
	}

	// Merge the wrapped object over the envelope, so one lookup reaches both halves.
	src := outer
	if key, wrapped := payloadWrapper[on]; wrapped {
		inner, ok := outer[key].(map[string]any)
		if !ok {
			return nil
		}
		src = make(map[string]any, len(outer)+len(inner))
		for k, v := range outer {
			if k != key {
				src[k] = v
			}
		}
		for k, v := range inner {
			src[k] = v
		}
	}

	aliases := payloadKeys[on]
	out := map[string]any{}
	for _, spec := range eventFields[on] {
		key := spec.Name
		// The alias is a fallback, not an override: a producer that starts sending the
		// catalog's own name must win over the table that was compensating for it.
		if _, direct := src[spec.Name]; !direct {
			if alias, ok := aliases[spec.Name]; ok {
				key = alias
			}
		}
		if v, ok := src[key]; ok && v != nil {
			out[spec.Name] = v
		}
	}
	return out
}

// NewMapSubject reads condition fields off a projection.
//
// The same conversions JSONSubject makes, over a map that is already decoded. A bool becomes
// the word "true" or "false" because that is what a KindBool field's operators compare
// against, and what the editor offers in its dropdown.
func NewMapSubject(fields map[string]any) Subject { return mapSubject(fields) }

type mapSubject map[string]any

func (m mapSubject) Value(field string) FieldValue {
	v, ok := m[field]
	if !ok || v == nil {
		return FieldValue{}
	}
	switch t := v.(type) {
	case string:
		return Text(t)
	case float64:
		return Number(t)
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return Number(f)
		}
		return Text(t.String())
	case bool:
		return Text(strconv.FormatBool(t))
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return FieldValue{}
		}
		return Raw(b)
	}
}
