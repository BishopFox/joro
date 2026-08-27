package trigger

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/proxy"
)

// Compiled is a trigger resolved against the field catalog, with every regexp built and
// every logic node's inputs ordered cheapest-first.
//
// Built once when the trigger store changes and never on the dispatch path, which is the
// same compile-once shape detect.Engine.rebuildLocked uses for its rule set.
type Compiled struct {
	On string

	// nodes is the expression, in no particular order; root indexes the node feeding the
	// run node, or -1 for an unconditional trigger.
	nodes []compiledNode
	root  int

	// Poisoned marks a trigger holding something this build cannot evaluate — an unknown
	// field or operator, a cycle, a node type it does not know. It matches nothing.
	//
	// The polarity is the whole point and reads backwards if inferred. A trigger exists to
	// narrow when an automation runs; a part of it that cannot be read is a narrowing that
	// is not being applied, so honoring the rest would run the automation in cases the
	// operator wrote a rule to exclude. Refusing is the failure they notice; running is
	// the one they do not.
	//
	// Validate rejects these on the write path, so reaching here means a hand-edited
	// triggers.json, a file from a newer Joro, or a reference to a trigger that no longer
	// exists — and that last case is why "missing" must never resolve to "unconditional".
	Poisoned bool
	Reason   string
}

type compiledNode struct {
	kind string

	// cond is set for a condition node.
	cond compiledCondition

	// children indexes the inputs of a logic node, cheapest first.
	children []int

	// cost is the most expensive field anywhere beneath this node, so a parent can order
	// a subtree by what it might have to read rather than by its own type.
	cost int
}

type compiledCondition struct {
	field string
	kind  string
	op    string

	// value is the comparand, already lowercased when cs is false, so the evaluator folds
	// only the haystack and the two sides always agree.
	value  string
	cs     bool
	negate bool

	re     *regexp.Regexp
	lit    []byte // literal prefix of re, when it has one: a cheap prescreen before the match
	status func(int) bool
	num    float64
	set    []string
}

// Poison returns a compiled trigger that matches nothing, for a reference that cannot be
// resolved at all.
func Poison(reason string) *Compiled {
	return &Compiled{Poisoned: true, Reason: reason}
}

// Compile resolves a trigger for evaluation. It never returns nil: a trigger that cannot
// be compiled comes back poisoned rather than absent, because an absent filter means "no
// filter" and that is the opposite of what happened.
func Compile(t *Trigger) *Compiled {
	if FieldIndex(t.On) == nil && Dispatched(t.On) {
		return Poison(fmt.Sprintf("event %q carries nothing to test", t.On))
	}
	out := &Compiled{On: t.On, root: -1}

	// Index the graph. Structural problems are poison rather than errors here: Validate
	// already reported them to whoever could fix them, and this path serves a file that
	// got past it.
	byID := make(map[string]*Node, len(t.Graph.Nodes))
	for i := range t.Graph.Nodes {
		byID[t.Graph.Nodes[i].ID] = &t.Graph.Nodes[i]
	}
	inputs := make(map[string][]string, len(t.Graph.Nodes))
	var fire string
	for i := range t.Graph.Nodes {
		if t.Graph.Nodes[i].Type == NodeFire {
			if fire != "" {
				return Poison("the graph has more than one run node")
			}
			fire = t.Graph.Nodes[i].ID
		}
	}
	if fire == "" {
		// No run node at all. An empty graph is what a built-in has, and it fires on
		// every event; a graph with conditions but no run node is a file that never
		// passed Validate, and it must not inherit that meaning.
		if len(t.Graph.Nodes) == 0 {
			return out
		}
		return Poison("the graph has no run node, so nothing says when to run")
	}
	for _, e := range t.Graph.Edges {
		from, to := byID[e.From], byID[e.To]
		if from == nil || to == nil {
			return Poison(fmt.Sprintf("a connection names %q, which is not a node", e.From+" -> "+e.To))
		}
		if from.Type == NodeEvent {
			continue // the event wire carries no value into the expression
		}
		inputs[e.To] = append(inputs[e.To], e.From)
	}

	if err := t.Graph.Validate(t.On); err != nil {
		return Poison(err.Error())
	}

	fields := FieldIndex(t.On)
	index := make(map[string]int, len(t.Graph.Nodes))
	var build func(id string, depth int) (int, error)
	build = func(id string, depth int) (int, error) {
		if depth > MaxNodes {
			return 0, fmt.Errorf("the connections nest too deeply")
		}
		// A node feeding two parents is compiled once and evaluated once; Validate has
		// already ruled out a cycle, so revisiting one is sharing rather than recursion.
		if i, ok := index[id]; ok {
			return i, nil
		}
		n := byID[id]
		if n == nil {
			return 0, fmt.Errorf("node %q does not exist", id)
		}

		cn := compiledNode{kind: n.Type}
		switch n.Type {
		case NodeCondition:
			cc, err := compileCondition(n, fields)
			if err != nil {
				return 0, err
			}
			cn.cond = cc
			cn.cost = fields[n.Field].cost

		case NodeAll, NodeAny, NodeNot:
			for _, src := range inputs[id] {
				ci, err := build(src, depth+1)
				if err != nil {
					return 0, err
				}
				cn.children = append(cn.children, ci)
			}
			// Cheapest first, so short-circuiting skips the expensive half. The cost of a
			// logic node is the worst thing under it, which is what lets a parent order
			// whole subtrees rather than only its immediate conditions.
			slot := len(out.nodes)
			out.nodes = append(out.nodes, cn)
			index[id] = slot
			for _, ci := range out.nodes[slot].children {
				out.nodes[slot].cost = max(out.nodes[slot].cost, out.nodes[ci].cost)
			}
			kids := out.nodes[slot].children
			sort.SliceStable(kids, func(a, b int) bool {
				return out.nodes[kids[a]].cost < out.nodes[kids[b]].cost
			})
			return slot, nil

		default:
			return 0, fmt.Errorf("node %q has type %q, which cannot be evaluated", id, n.Type)
		}

		slot := len(out.nodes)
		out.nodes = append(out.nodes, cn)
		index[id] = slot
		return slot, nil
	}

	src := inputs[fire]
	if len(src) == 0 {
		return out // nothing wired to the run node: fires on every event
	}
	if len(src) > 1 {
		return Poison("the run node has more than one input")
	}
	root, err := build(src[0], 0)
	if err != nil {
		return Poison(err.Error())
	}
	out.root = root
	return out
}

func compileCondition(n *Node, fields map[string]FieldSpec) (compiledCondition, error) {
	spec, ok := fields[n.Field]
	if !ok {
		return compiledCondition{}, fmt.Errorf("condition %q tests %q, which this event does not carry",
			n.ID, n.Field)
	}
	if !slices.Contains(spec.Ops, n.Op) {
		return compiledCondition{}, fmt.Errorf("condition %q: %q does not take %q", n.ID, n.Field, n.Op)
	}

	cc := compiledCondition{
		field:  n.Field,
		kind:   spec.Kind,
		op:     n.Op,
		value:  n.Value,
		cs:     n.CaseSensitive,
		negate: n.Negate,
	}
	if !cc.cs {
		cc.value = strings.ToLower(cc.value)
	}

	switch {
	case n.Op == OpStatus:
		cc.status = proxy.NewStatusPredicate(n.Value)

	case n.Op == OpIn:
		for _, part := range strings.Split(n.Value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				if !n.CaseSensitive {
					part = strings.ToLower(part)
				}
				cc.set = append(cc.set, part)
			}
		}

	case n.Op == OpGt, n.Op == OpLt, n.Op == OpGte, n.Op == OpLte:
		f, err := strconv.ParseFloat(strings.TrimSpace(n.Value), 64)
		if err != nil {
			return compiledCondition{}, fmt.Errorf("condition %q: %q needs a number", n.ID, n.Op)
		}
		cc.num = f

	case spec.Kind == KindBytes:
		// Every string operator on a byte field becomes one regexp. A body is up to a
		// megabyte, and the alternative for a case-insensitive comparison is a lowercased
		// copy of it per condition per candidate.
		re, err := compileBytesOp(n)
		if err != nil {
			return compiledCondition{}, fmt.Errorf("condition %q: %v", n.ID, err)
		}
		cc.re = re
		if re != nil {
			if prefix, _ := re.LiteralPrefix(); prefix != "" {
				cc.lit = []byte(prefix)
			}
		}

	case n.Op == OpMatches:
		pattern := n.Value
		if !n.CaseSensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return compiledCondition{}, fmt.Errorf("condition %q: %v", n.ID, err)
		}
		cc.re = re

	case n.Op == OpGlob:
		if _, err := filepath.Match(n.Value, ""); err != nil {
			return compiledCondition{}, fmt.Errorf("condition %q: %q is not a valid glob", n.ID, n.Value)
		}
	}
	return cc, nil
}

// compileBytesOp turns a string operator on a byte field into a single regexp.
func compileBytesOp(n *Node) (*regexp.Regexp, error) {
	var pattern string
	switch n.Op {
	case OpExists:
		return nil, nil
	case OpMatches:
		pattern = n.Value
	case OpContains:
		pattern = regexp.QuoteMeta(n.Value)
	case OpPrefix:
		pattern = `\A` + regexp.QuoteMeta(n.Value)
	case OpSuffix:
		pattern = regexp.QuoteMeta(n.Value) + `\z`
	default:
		return nil, fmt.Errorf("operator %q does not apply to a byte field", n.Op)
	}
	if !n.CaseSensitive {
		pattern = "(?i)" + pattern
	}
	return regexp.Compile(pattern)
}
