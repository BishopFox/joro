package trigger

import (
	"github.com/BishopFox/joro/internal/proxy"
)

// TestResult is what a dry run of a trigger reports.
//
// Scanned and Count are both here because the pair is the answer: forty of the last fifty
// captures matching says something different about a filter than two of them do, and a
// count alone says neither.
type TestResult struct {
	Valid   bool     `json:"valid"`
	Error   string   `json:"error,omitempty"`
	Orphans []string `json:"orphans,omitempty"`
	Scanned int      `json:"scanned"`
	Count   int      `json:"count"`
	Matched []Hit    `json:"matched"`

	// Replayable is false for an event with no corpus to replay against — a finding, a
	// finished campaign, a finished run. The graph is still reported valid or not; there
	// is simply nothing to try it on, and saying so beats reporting zero matches out of
	// zero scanned and letting the operator read it as a rejection.
	Replayable bool `json:"replayable"`
}

// Hit is one capture a trigger accepted, identified the way History identifies it.
type Hit struct {
	Seq         int    `json:"seq"`
	Method      string `json:"method"`
	Host        string `json:"host"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
}

// Bounds on one preview. It runs on an operator's request rather than on the dispatcher
// goroutine, so it can afford more than a dispatch pass — but it is reachable from the
// canvas on every edit they choose to test, so not much more.
const (
	DefaultTestLimit = 50
	MaxTestLimit     = 200
)

// Test replays a trigger over the most recent captures.
//
// The point of it is that a graph is guesswork until it is tried: RE2 is not JavaScript's
// regexp engine, a body condition silently never matches a compressed or binary response,
// and "contains" against the wrong half of a transaction looks identical to a filter that
// is simply too narrow. This is the same division DetectRuleModal already relies on — the
// client may preview, the server is what decides.
func Test(store *proxy.Store, t Trigger, limit int) TestResult {
	out := TestResult{Matched: []Hit{}}

	t.Normalize()
	if err := t.Validate(); err != nil {
		out.Error = err.Error()
		return out
	}
	out.Valid = true
	out.Orphans = t.Graph.Orphans()

	if t.On != EventRequestCaptured || store == nil {
		return out
	}
	out.Replayable = true

	switch {
	case limit <= 0:
		limit = DefaultTestLimit
	case limit > MaxTestLimit:
		limit = MaxTestLimit
	}

	// The most recent captures, read the way the dispatcher reads them. Store.List would
	// return the oldest instead: its ring buffer is oldest-first and it slices from the
	// front, so a limit there means "the first N", which for a preview is the
	// engagement's history rather than what the operator is looking at.
	from := max(store.LastSeq()-limit, 0)
	compiled := Compile(&t)
	for _, it := range store.SinceSeq(from, limit) {
		out.Scanned++
		if !compiled.Matches(NewRequestSubject(it)) {
			continue
		}
		out.Count++
		out.Matched = append(out.Matched, Hit{
			Seq: it.Seq, Method: it.Method, Host: it.Host,
			URL: it.URL, Status: it.StatusCode, ContentType: it.ContentType,
		})
	}
	return out
}

// Layout constants, shared with the canvas so a graph Joro seeds and one the operator
// drags use the same units.
const (
	colWidth  = 260
	rowHeight = 110
)

// seedCondition is the first condition a new trigger starts with, per event.
//
// A real starting point rather than a blank one: each is both valid on its own and the
// thing an operator most often wants from that event, so the common case is edit-one-value
// rather than build-from-nothing. A blank condition would also fail Validate — most
// operators need a value — so the canvas would open on an error.
var seedCondition = map[string]Node{
	EventRequestCaptured:    {Field: "status", Op: OpStatus, Value: "2xx"},
	EventDetectFinding:      {Field: "severity", Op: OpIn, Value: "critical,high"},
	EventFuzzerComplete:     {Field: "status", Op: OpEq, Value: "complete"},
	EventAutomationComplete: {Field: "outcome", Op: OpEq, Value: "success"},
}

// SeedGraph returns the graph a new trigger starts from: the event, one condition, and the
// run node, already wired.
//
// Seeded rather than empty because an empty canvas does not teach the shape. Three
// connected boxes show what a trigger is in one glance — an event, something asked of it,
// and the thing that happens.
func SeedGraph(on string) Graph {
	g := Graph{
		Nodes: []Node{
			{ID: "event", Type: NodeEvent, X: 0, Y: rowHeight},
			{ID: "fire", Type: NodeFire, X: colWidth * 2, Y: rowHeight},
		},
		Edges: []Edge{},
	}
	seed, ok := seedCondition[on]
	if !ok {
		return g
	}
	seed.ID, seed.Type, seed.X, seed.Y = "c1", NodeCondition, colWidth, rowHeight
	g.Nodes = append(g.Nodes, seed)
	g.Edges = append(g.Edges,
		Edge{From: "event", To: "c1"},
		Edge{From: "c1", To: "fire"},
	)
	return g
}
