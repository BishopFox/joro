// Package trigger owns what makes an automation run: the event it watches, and the graph
// of conditions an event has to satisfy before it is worth a run.
//
// A trigger is a first-class named object rather than a field of the automation that uses
// it. That is the whole shape of this package: several automations can point at one
// trigger, an operator authors and tests one on its own, and fixing it fixes every user at
// once. The cost is a reference that can dangle, and every rule below about missing or
// unreadable triggers exists to make that failure loud rather than silent.
//
// It imports proxy and detect and nothing else of Joro's, so it can be evaluated anywhere
// a captured request is in hand. jsautomation imports this; nothing here imports back.
package trigger

import (
	"fmt"
	"strings"
)

// The events the dispatcher watches. These are Joro's own event type strings, not a
// parallel vocabulary — a trigger subscribes to something that already happens.
//
// automation.completed is the one name here that is not broadcast on the bus. Per-run
// events would be a firehose an agent controls, so a finished run reaches the dispatcher
// in process; see jsautomation.Dispatcher.RunCompleted.
const (
	EventManual             = "manual"
	EventRequestSelected    = "request.selected"
	EventRequestCaptured    = "request.captured"
	EventDetectFinding      = "detect.finding"
	EventFuzzerComplete     = "fuzzer.complete"
	EventAutomationComplete = "automation.completed"
)

// EventLens labels a run the request/response viewer started to render a lens tab. Not an
// event anything subscribes to: declaring a lens is what enables it.
const EventLens = "lens"

// Events lists every event a trigger may watch, in the order the UI shows them: the two
// the operator starts by hand first, then cheapest-to-reason-about to most consequential.
var Events = []string{
	EventManual,
	EventRequestSelected,
	EventDetectFinding,
	EventFuzzerComplete,
	EventAutomationComplete,
	EventRequestCaptured,
}

// Dispatched reports whether the dispatcher watches this event.
//
// Membership first, so an event name this build does not know is not dispatched rather
// than assumed to be. The two hand-started ones are then excluded because the operator
// starts both, which is also why neither takes conditions — filtering an event you chose
// yourself is a switch that does nothing.
func Dispatched(event string) bool {
	return IsBuiltin(event) && event != EventManual && event != EventRequestSelected
}

// Node types.
const (
	NodeEvent     = "event"
	NodeCondition = "condition"
	NodeAll       = "all"
	NodeAny       = "any"
	NodeNot       = "not"
	NodeFire      = "fire"
)

// NodeTypes lists every node type, in palette order.
var NodeTypes = []string{NodeEvent, NodeCondition, NodeAll, NodeAny, NodeNot, NodeFire}

// Bounds on one trigger. Small on purpose: the evaluator runs on the dispatcher goroutine,
// which also drains Joro's event bus, and these multiply with the number of armed
// automations.
const (
	MaxNodes      = 64
	MaxEdges      = 128
	MaxValueLen   = 512
	MaxIDLen      = 64
	MaxNameLen    = 80
	MaxDescLen    = 400
	MaxCoordinate = 100_000
)

// Trigger is one reason an automation runs.
type Trigger struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// On is the event this watches. A trigger watches exactly one: the dispatcher
	// batches per event kind and each kind's payload has its own shape, so a second
	// source would leave a run with no coherent payload to receive.
	On string `json:"on"`

	Graph Graph `json:"graph"`

	// Builtin and Problem are computed on the way out and never persisted.
	//
	// Problem carries why a stored trigger will not fire — an unknown field, a cycle, a
	// node this build does not understand. It is here rather than left to a log because
	// the operator's only other signal would be an automation that quietly stops running.
	Builtin bool   `json:"builtin,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// Graph is the boolean expression that decides whether an event is worth a run.
//
// Ports are implied by node type rather than named on the edge: an edge leaving the event
// node carries the event, and every other edge carries a boolean. That halves the schema
// and removes the one thing a hand-editor would most easily get wrong, at the cost of
// this sentence having to exist.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Node is one box on the canvas.
type Node struct {
	ID   string  `json:"id"`
	Type string  `json:"type"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`

	// Condition nodes only. See catalog.go for which fields and operators pair.
	Field         string `json:"field,omitempty"`
	Op            string `json:"op,omitempty"`
	Value         string `json:"value,omitempty"`
	Negate        bool   `json:"negate,omitempty"`
	CaseSensitive bool   `json:"caseSensitive,omitempty"`
}

// Edge is one wire.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// BuiltinTriggers returns the unconditional trigger for every event, which is what an
// automation gets by naming an event directly.
//
// Synthesized rather than stored. They are not rows an operator can edit or delete, and a
// shipped file holding them would be one more thing that could drift from the constants
// above or be hand-edited into disagreeing with them.
func BuiltinTriggers() []Trigger {
	out := make([]Trigger, 0, len(Events))
	for _, e := range Events {
		out = append(out, Trigger{
			ID:          e,
			Name:        e,
			Description: builtinDescriptions[e],
			On:          e,
			Builtin:     true,
		})
	}
	return out
}

var builtinDescriptions = map[string]string{
	EventManual:             "Runs only when you start it, or when an agent asks for it by id.",
	EventRequestSelected:    "Runs against one captured request you pick from History.",
	EventRequestCaptured:    "Runs on every proxied request, once its response is captured.",
	EventDetectFinding:      "Runs on every finding Detect reports.",
	EventFuzzerComplete:     "Runs when a fuzzing campaign finishes.",
	EventAutomationComplete: "Runs when any other automation finishes.",
}

// IsBuiltin reports whether a reference names an event directly rather than a custom
// trigger.
func IsBuiltin(ref string) bool {
	for _, e := range Events {
		if ref == e {
			return true
		}
	}
	return false
}

// Normalize trims and fills defaults. Called before Validate so a trigger that omits an
// optional field is accepted rather than corrected by the operator.
func (t *Trigger) Normalize() {
	t.ID = strings.ToLower(strings.TrimSpace(t.ID))
	t.Name = strings.TrimSpace(t.Name)
	t.Description = strings.TrimSpace(t.Description)
	t.On = strings.TrimSpace(t.On)
	if t.Name == "" {
		t.Name = t.ID
	}
	for i := range t.Graph.Nodes {
		n := &t.Graph.Nodes[i]
		n.ID = strings.TrimSpace(n.ID)
		n.Type = strings.ToLower(strings.TrimSpace(n.Type))
		n.Field = strings.TrimSpace(n.Field)
		n.Op = strings.ToLower(strings.TrimSpace(n.Op))
	}
}

// Validate reports why a trigger cannot be stored. Messages name the node and the rule,
// because the audience is as often the canvas showing an inline error as a person reading
// a file.
//
// This is the write path only. A trigger already on disk that fails here still loads and
// still lists — Compile poisons it so it never fires, and Problem says why. The two
// directions are deliberate: reject what you can explain to someone who is standing
// there, refuse to act on what you cannot.
func (t *Trigger) Validate() error {
	switch {
	case t.ID == "":
		return fmt.Errorf("id is required")
	case len(t.ID) > MaxIDLen:
		return fmt.Errorf("id is %d characters, over the %d limit", len(t.ID), MaxIDLen)
	case !idPattern.MatchString(t.ID):
		return fmt.Errorf("id %q is invalid: use lowercase letters, digits, hyphen and "+
			"underscore, starting with a letter or digit", t.ID)
	case IsBuiltin(t.ID):
		return fmt.Errorf("%q is the name of a built-in trigger; choose another id", t.ID)
	case len(t.Name) > MaxNameLen:
		return fmt.Errorf("name is %d characters, over the %d limit", len(t.Name), MaxNameLen)
	case len(t.Description) > MaxDescLen:
		return fmt.Errorf("description is %d characters, over the %d limit",
			len(t.Description), MaxDescLen)
	case !Dispatched(t.On):
		if IsBuiltin(t.On) {
			return fmt.Errorf("%q is started by hand, so a trigger for it would filter an "+
				"event you already chose", t.On)
		}
		return fmt.Errorf("unknown event %q (known: %s)", t.On, strings.Join(dispatchedEvents(), ", "))
	}
	return t.Graph.Validate(t.On)
}

func dispatchedEvents() []string {
	var out []string
	for _, e := range Events {
		if Dispatched(e) {
			out = append(out, e)
		}
	}
	return out
}
