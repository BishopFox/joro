package jsautomation

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
)

// The visual authoring document for a script automation, stored and bounded here and
// interpreted nowhere.
//
// Joro does not compile this. The entrypoint .js is what runs, and the canvas in the
// browser is what generates it — the compiler lives there because its output is source text
// consumed by a save, not an evaluator something on this side has to run. internal/trigger
// is the other way round for the same reason: a trigger's graph compiles to a predicate the
// dispatcher evaluates on every event, so it has to compile where the events are.
//
// The consequence worth stating is what it is not. A graph is not a permission surface: a
// run's grants come from the SDK bundle and never from what its source asks for, so
// generated JavaScript reaches exactly what hand-written JavaScript reaches. Nothing here
// widens anything, which is why storing an opaque blob is safe — and no token can put one
// here anyway, because scriptInstallArgs has no graph field.
//
// A token that replaces a package's source drops its graph with it, because the manifest it
// submits carries none. That is the right answer rather than an oversight: the canvas
// described the code that used to be there, and keeping it would mean a later operator Save
// silently reverted what the token wrote.
//
// Node payloads are therefore json.RawMessage. Go has no reason to know what a "compare"
// node's operator is, and a Go mirror of every node kind would be a second definition of
// the language to keep in step with the one that actually reads it.
type FlowGraph struct {
	Nodes []FlowNode `json:"nodes"`
	Edges []FlowEdge `json:"edges"`
}

// FlowNode is one box. Data is the kind's own configuration, opaque here.
type FlowNode struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	X    float64         `json:"x"`
	Y    float64         `json:"y"`
	Data json.RawMessage `json:"data,omitempty"`
}

// FlowEdge is one wire. Ports are named, unlike a trigger edge where the node type implies
// them: a call node has one input per argument of the method it calls.
type FlowEdge struct {
	From     string `json:"from"`
	FromPort string `json:"fromPort,omitempty"`
	To       string `json:"to"`
	ToPort   string `json:"toPort"`
}

// Bounds, mirrored in web/src/lib/flowGraph.ts. Twice internal/trigger's, because a program
// is a bigger thing than a predicate. Edited together — nothing here fails a build if the
// two drift, and the frontend is the half that stops an operator exceeding them.
const (
	MaxFlowNodes     = 128
	MaxFlowEdges     = 256
	MaxFlowNodeIDLen = 64
	// One node's configuration. A literal or a template is the large case, and the graph
	// travels inside the same bounded request as the source it generates.
	MaxFlowDataBytes = 16 << 10
	MaxFlowBytes     = 512 << 10
)

var flowNodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_:.-]*$`)

// validateFlow bounds a graph on the way in.
//
// Called only from the write path, never from Manifest.Validate. Validate runs on every
// Load, and a graph that a hand edit pushed past a bound would otherwise make the whole
// package vanish rather than report itself — the same rule the trigger references follow,
// and the same polarity as trigger.Store, which loads an unreadable trigger so the operator
// can see it and fix it.
func validateFlow(g *FlowGraph) error {
	if g == nil {
		return nil
	}
	switch {
	case len(g.Nodes) > MaxFlowNodes:
		return fmt.Errorf("the graph has %d boxes, over the %d limit", len(g.Nodes), MaxFlowNodes)
	case len(g.Edges) > MaxFlowEdges:
		return fmt.Errorf("the graph has %d wires, over the %d limit", len(g.Edges), MaxFlowEdges)
	}

	seen := make(map[string]struct{}, len(g.Nodes))
	for _, n := range g.Nodes {
		switch {
		case n.ID == "":
			return fmt.Errorf("a graph box has no id")
		case len(n.ID) > MaxFlowNodeIDLen:
			return fmt.Errorf("box id %q is %d characters, over the %d limit", n.ID, len(n.ID), MaxFlowNodeIDLen)
		case !flowNodeIDPattern.MatchString(n.ID):
			return fmt.Errorf("box id %q is invalid", n.ID)
		case n.Type == "":
			return fmt.Errorf("box %q has no kind", n.ID)
		case len(n.Data) > MaxFlowDataBytes:
			return fmt.Errorf("box %q carries %d bytes, over the %d limit", n.ID, len(n.Data), MaxFlowDataBytes)
		}
		if _, dup := seen[n.ID]; dup {
			return fmt.Errorf("two graph boxes share the id %q", n.ID)
		}
		seen[n.ID] = struct{}{}
		// A coordinate that is not a number cannot be written back out as JSON, so it would
		// turn one bad drag into a package that no longer serializes.
		if math.IsNaN(n.X) || math.IsNaN(n.Y) || math.IsInf(n.X, 0) || math.IsInf(n.Y, 0) {
			return fmt.Errorf("box %q sits nowhere", n.ID)
		}
	}

	// Endpoints have to exist. Acyclicity, port kinds and arity are not checked: they are
	// the language's rules, the compiler that reads them is in the browser, and a second
	// implementation here would be a second thing to keep in step for no gain — a graph
	// that will not compile produces no source, and the source is what runs.
	for _, e := range g.Edges {
		if _, ok := seen[e.From]; !ok {
			return fmt.Errorf("a wire starts at %q, which is not a box in this graph", e.From)
		}
		if _, ok := seen[e.To]; !ok {
			return fmt.Errorf("a wire ends at %q, which is not a box in this graph", e.To)
		}
	}

	if b, err := json.Marshal(g); err == nil && len(b) > MaxFlowBytes {
		return fmt.Errorf("the graph is %d bytes, over the %d limit", len(b), MaxFlowBytes)
	}
	return nil
}
