package trigger

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// idPattern is the plugin and automation name pattern, reused so an operator learns one
// rule for every id Joro asks them for. It excludes '.', which is what keeps a custom id
// from colliding with an event name — every event but manual and lens contains one, and
// Validate rejects those two explicitly.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// nodePattern admits the ids a canvas generates. Looser than idPattern because these are
// never path components and never typed by hand.
var nodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// Validate reports why a graph cannot be stored, against the field catalog for one event.
//
// The structural rules are all here rather than split between here and the compiler, so
// there is one place to read what a well-formed graph is. The compiler re-derives what it
// needs and fails closed on anything it cannot read, which covers a file this build did
// not write.
func (g *Graph) Validate(on string) error {
	if len(g.Nodes) > MaxNodes {
		return fmt.Errorf("the graph has %d nodes, over the %d limit", len(g.Nodes), MaxNodes)
	}
	if len(g.Edges) > MaxEdges {
		return fmt.Errorf("the graph has %d connections, over the %d limit", len(g.Edges), MaxEdges)
	}

	fields := FieldIndex(on)
	if fields == nil {
		return fmt.Errorf("%q carries nothing to test", on)
	}

	byID := make(map[string]*Node, len(g.Nodes))
	var events, fires int
	for i := range g.Nodes {
		n := &g.Nodes[i]
		switch {
		case n.ID == "":
			return fmt.Errorf("every node needs an id")
		case !nodePattern.MatchString(n.ID):
			return fmt.Errorf("node id %q is invalid", n.ID)
		case byID[n.ID] != nil:
			return fmt.Errorf("two nodes share the id %q", n.ID)
		case !slices.Contains(NodeTypes, n.Type):
			return fmt.Errorf("node %q has unknown type %q (known: %s)",
				n.ID, n.Type, strings.Join(NodeTypes, ", "))
		// Positions are the operator's, not the evaluator's, so they are bounded rather
		// than meaningful. A NaN would render a node nowhere and be impossible to find.
		case math.IsNaN(n.X) || math.IsNaN(n.Y) ||
			math.Abs(n.X) > MaxCoordinate || math.Abs(n.Y) > MaxCoordinate:
			return fmt.Errorf("node %q sits outside the canvas", n.ID)
		}
		byID[n.ID] = n

		switch n.Type {
		case NodeEvent:
			events++
		case NodeFire:
			fires++
		case NodeCondition:
			if err := validateCondition(n, fields); err != nil {
				return err
			}
		}
	}
	if events != 1 {
		return fmt.Errorf("a graph needs exactly one event node, and this has %d", events)
	}
	if fires != 1 {
		return fmt.Errorf("a graph needs exactly one run node, and this has %d", fires)
	}

	// Count what arrives where, so the arity rules below read as arity rules.
	boolIn := make(map[string]int, len(g.Nodes))
	eventIn := make(map[string]int, len(g.Nodes))
	seen := make(map[Edge]struct{}, len(g.Edges))
	for _, e := range g.Edges {
		from, to := byID[e.From], byID[e.To]
		switch {
		case from == nil:
			return fmt.Errorf("a connection starts at %q, which is not a node", e.From)
		case to == nil:
			return fmt.Errorf("a connection ends at %q, which is not a node", e.To)
		case e.From == e.To:
			return fmt.Errorf("node %q is connected to itself", e.From)
		}
		if _, dup := seen[e]; dup {
			return fmt.Errorf("%q and %q are connected twice", e.From, e.To)
		}
		seen[e] = struct{}{}

		if from.Type == NodeEvent {
			if to.Type != NodeCondition {
				return fmt.Errorf("the event node feeds conditions, and %q is a %s node",
					to.ID, to.Type)
			}
			eventIn[to.ID]++
			continue
		}
		if from.Type == NodeFire {
			return fmt.Errorf("the run node is the end of the graph; nothing leads out of it")
		}
		if to.Type == NodeCondition || to.Type == NodeEvent {
			return fmt.Errorf("%q cannot take a connection from %q: a %s node produces a "+
				"true or false, which only logic and the run node accept", to.ID, from.ID, from.Type)
		}
		boolIn[to.ID]++
	}

	for i := range g.Nodes {
		n := &g.Nodes[i]
		switch n.Type {
		case NodeCondition:
			// Required rather than implied, even though there is only one event node it
			// could come from. The wire is what makes a condition visibly about the event
			// rather than free-floating, and the canvas draws it on creation so the
			// operator never makes it by hand.
			if eventIn[n.ID] != 1 {
				return fmt.Errorf("condition %q is not connected to the event", n.ID)
			}
		case NodeNot:
			if boolIn[n.ID] != 1 {
				return fmt.Errorf("a NOT node inverts one input, and %q has %d", n.ID, boolIn[n.ID])
			}
		case NodeAll, NodeAny:
			if boolIn[n.ID] == 0 {
				return fmt.Errorf("%s node %q has nothing connected to it", strings.ToUpper(n.Type), n.ID)
			}
		case NodeFire:
			// Zero is allowed and means unconditional, which is what a built-in is and
			// what a half-built graph starts as.
			if boolIn[n.ID] > 1 {
				return fmt.Errorf("the run node takes one input; combine %d with an ALL or ANY node",
					boolIn[n.ID])
			}
		}
	}

	if cycle := findCycle(g, byID); cycle != "" {
		return fmt.Errorf("the connections form a loop through %s, so nothing decides first", cycle)
	}
	return nil
}

func validateCondition(n *Node, fields map[string]FieldSpec) error {
	spec, ok := fields[n.Field]
	if !ok {
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		slices.Sort(names)
		return fmt.Errorf("condition %q tests %q, which this event does not carry (it has: %s)",
			n.ID, n.Field, strings.Join(names, ", "))
	}
	if !slices.Contains(spec.Ops, n.Op) {
		return fmt.Errorf("condition %q: %q does not take %q (it takes: %s)",
			n.ID, n.Field, n.Op, strings.Join(spec.Ops, ", "))
	}
	if len(n.Value) > MaxValueLen {
		return fmt.Errorf("condition %q has a %d character value, over the %d limit",
			n.ID, len(n.Value), MaxValueLen)
	}
	if n.Op != OpExists && strings.TrimSpace(n.Value) == "" {
		return fmt.Errorf("condition %q needs a value for %q", n.ID, n.Op)
	}

	switch n.Op {
	case OpMatches:
		if _, err := regexp.Compile(n.Value); err != nil {
			return fmt.Errorf("condition %q: %v", n.ID, err)
		}
	case OpGlob:
		if _, err := filepath.Match(n.Value, ""); err != nil {
			return fmt.Errorf("condition %q: %q is not a valid glob", n.ID, n.Value)
		}
	case OpGt, OpLt, OpGte, OpLte:
		if _, err := strconv.ParseFloat(strings.TrimSpace(n.Value), 64); err != nil {
			return fmt.Errorf("condition %q: %q needs a number, not %q", n.ID, n.Op, n.Value)
		}
	}
	return nil
}

// findCycle returns a node id on a cycle, or "" when the graph is acyclic. Iterative
// three-colour DFS: a graph is bounded at MaxNodes, but recursion here would put a
// hand-edited file in charge of the stack.
func findCycle(g *Graph, byID map[string]*Node) string {
	out := make(map[string][]string, len(g.Nodes))
	for _, e := range g.Edges {
		if byID[e.From] != nil && byID[e.From].Type == NodeEvent {
			continue // event wires cannot close a loop; nothing leads back into the event
		}
		out[e.From] = append(out[e.From], e.To)
	}

	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(g.Nodes))

	type frame struct {
		id   string
		next int
	}
	for _, n := range g.Nodes {
		if color[n.ID] != white {
			continue
		}
		stack := []frame{{id: n.ID}}
		color[n.ID] = grey
		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			kids := out[top.id]
			if top.next >= len(kids) {
				color[top.id] = black
				stack = stack[:len(stack)-1]
				continue
			}
			kid := kids[top.next]
			top.next++
			switch color[kid] {
			case grey:
				return kid
			case white:
				color[kid] = grey
				stack = append(stack, frame{id: kid})
			}
		}
	}
	return ""
}

// Orphans lists condition and logic nodes that nothing reaches from the run node.
//
// Not an error: a half-built graph is the normal state of one being edited. But an
// orphaned condition is a filter the operator wrote and is not getting, which makes the
// trigger fire more broadly than the picture suggests — so it is reported everywhere the
// graph is, rather than left to be noticed.
func (g *Graph) Orphans() []string {
	var fire string
	byID := make(map[string]*Node, len(g.Nodes))
	for i := range g.Nodes {
		byID[g.Nodes[i].ID] = &g.Nodes[i]
		if g.Nodes[i].Type == NodeFire {
			fire = g.Nodes[i].ID
		}
	}
	if fire == "" {
		return nil
	}

	in := make(map[string][]string, len(g.Nodes))
	for _, e := range g.Edges {
		if from := byID[e.From]; from == nil || from.Type == NodeEvent {
			continue
		}
		in[e.To] = append(in[e.To], e.From)
	}

	reached := map[string]bool{fire: true}
	queue := []string{fire}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, src := range in[id] {
			if !reached[src] {
				reached[src] = true
				queue = append(queue, src)
			}
		}
	}

	var out []string
	for _, n := range g.Nodes {
		if n.Type == NodeEvent || n.Type == NodeFire || reached[n.ID] {
			continue
		}
		out = append(out, n.ID)
	}
	slices.Sort(out)
	return out
}
