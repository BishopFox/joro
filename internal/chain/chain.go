// Package chain models a multi-step workflow — a login, a checkout, a password
// reset — as an ordered chain of captured requests plus the data dependencies
// between them, and produces the mutated orderings that test whether the
// application enforces its own sequence.
//
// # Nothing here sends
//
// Like internal/apispec, this package is structurally unable to reach the
// network: no function takes a context.Context and nothing socket-capable is
// imported. A chain renders to raw request bytes and internal/chainrun puts them
// on the wire through Joro's own proxy, which is what keeps scope, Match &
// Replace, Custom Data and intercept applying to a replay exactly as they apply
// to browser traffic. A send path private to this package is what would break it.
//
// # The whole mutation vocabulary is an ordered list
//
// A Variant is an ordered list of step references. Omit an entry and the step is
// skipped; list an entry twice and it repeats; permute the entries and the order
// changes. The three verbs an operator reaches for are one concept, so there is
// one code path to execute them and one place to be wrong.
//
// # Why a sink is byte spans and a source is an extractor
//
// The two ends of a dependency are addressed differently, on purpose.
//
// The consumer end is a recorded request — a fixed artifact Joro owns — so exact
// byte offsets are available and unambiguous. Literal search is the obvious
// alternative and it is wrong: an order id of "42" occurs in a dozen innocent
// places in a request, and replacing all of them corrupts it in ways that read
// as the server rejecting the replay. Spans cannot over-match. They are applied
// descending by offset so an earlier substitution never shifts a later one, and
// they are applied before any Edit, because an Edit invalidates offsets computed
// against the snapshot.
//
// The producer end is a response that has not happened yet and whose bytes Joro
// does not control, so an offset against the recording means nothing. It needs a
// rule that generalizes to a fresh response, which is what a Source is.
//
// # Why there is no cookie jar
//
// httptools.Contexts is the obvious reuse and its documented semantics are wrong
// here: Apply never overrides a cookie already present in the request, so a
// replay would keep sending the recorded session cookie rather than the fresh one
// the run's own first step just issued. A session cookie is simply another
// dependency — correlation finds it by matching a recorded Set-Cookie value
// against a later recorded Cookie header, and a cookie source resolves by name so
// a rotated session id still binds. One mechanism, no special case, and the
// dependency stays visible in the map, which is the thing this feature exists to
// show.
package chain

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/BishopFox/joro/internal/httptools"
)

// Bounds. A chain carries raw request bytes into the project file, so these are
// sized against that file staying openable rather than against any protocol
// limit.
const (
	// MaxChains bounds the project file. Each chain holds a snapshot of every
	// step's request bytes.
	MaxChains = 50

	// MaxSteps bounds one chain. A workflow long enough to exceed this is two
	// workflows.
	MaxSteps = 64

	// MaxBindings bounds one chain's dependency edges.
	MaxBindings = 128

	// MaxStepBytes caps one step's recorded request. A file-upload step would
	// otherwise put megabytes into every project save.
	MaxStepBytes = 1 << 20

	// MaxStepRespBytes caps the recorded response. It is kept only so that
	// correlation can be re-run after a project is reopened — by which time the
	// history rows it was built from are long evicted — and so the map can show
	// what a step answered. Neither needs a whole page, so this is much tighter
	// than the request cap.
	MaxStepRespBytes = 256 << 10

	// MaxSpansPerBinding bounds how many places one value may be injected. A
	// CSRF token in a header and a form field is two; more than a handful means
	// correlation matched something far too common.
	MaxSpansPerBinding = 32

	// MaxVariantsPerRun and MaxInstancesPerRun bound a sweep. The instance cap
	// matches apiscan.MaxRequestsPerRun because it bounds the same thing: real
	// requests leaving the machine.
	MaxVariantsPerRun  = 128
	MaxInstancesPerRun = 2000

	// MaxNameLen bounds operator-supplied labels.
	MaxNameLen = 80

	// MaxVarLen bounds a variable name.
	MaxVarLen = 64
)

// OnMissing values decide what a step does when a value it consumes was never
// produced — because the producing step was omitted, or moved after it.
const (
	// MissingFail refuses to send. This is the default, and it is the reason the
	// feature can be trusted: a step that silently sent a stale token would look
	// exactly like the application rejecting the request, turning "my replay fell
	// apart" into a false "the application enforced it".
	MissingFail = "fail"

	// MissingRecorded sends the originally captured value. Opt-in per binding,
	// because replaying a stale token is frequently the actual test.
	MissingRecorded = "recorded"
)

// Source kinds. Each must generalize to a response that has not happened yet.
const (
	SourceHeader  = "header"  // Name: header name
	SourceCookie  = "cookie"  // Name: cookie name, read from Set-Cookie
	SourceJSON    = "json"    // Path: dotted path with [i] indices
	SourceRegex   = "regex"   // Expr + Group
	SourceBetween = "between" // Prefix + Suffix literals
)

// Variant kinds. The kind decides which question the verdict answers, so it
// travels with the variant rather than being inferred from its shape.
const (
	VariantBaseline = "baseline"
	VariantOmit     = "omit"
	VariantRepeat   = "repeat"
	VariantMove     = "move"
)

// Span is a byte range in a step's recorded request bytes.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Source describes how to read a value out of a live response.
type Source struct {
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	Expr   string `json:"expr,omitempty"`
	Group  int    `json:"group,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Suffix string `json:"suffix,omitempty"`
}

// Binding is one data dependency: a value a later step consumes.
//
// Both ends live on one type so that an edge on the map is a binding and a
// binding is an edge, and so that a chain cannot hold an injection referring to a
// variable nothing produces.
type Binding struct {
	ID  string `json:"id"`
	Var string `json:"var"`

	// FromStep produces the value; Source reads it from that step's response.
	FromStep string `json:"fromStep"`
	Source   Source `json:"source"`

	// ToStep consumes it; Spans are byte ranges in that step's recorded ReqRaw.
	ToStep string `json:"toStep"`
	Spans  []Span `json:"spans"`

	// Recorded is the literal captured at build time. It is what MissingRecorded
	// sends, and it is what the map shows the operator so a binding can be read
	// without opening two raw panes.
	Recorded string `json:"recorded"`

	OnMissing string `json:"onMissing,omitempty"`

	// Auto marks a binding correlation proposed rather than one the operator
	// wrote, so the UI can offer to re-run correlation without discarding hand
	// work.
	Auto bool `json:"auto,omitempty"`
}

// Step is one recorded request.
//
// ReqRaw is a snapshot rather than a reference to a history row. The capture ring
// evicts, projects are saved and reopened on other machines, and a chain whose
// steps evaporate is worse than useless during an engagement.
type Step struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	ReqRaw []byte `json:"reqRaw"`

	// RespRaw is what this step answered when it was recorded. Correlation reads
	// it to find the values later steps consume; nothing at replay time does.
	RespRaw []byte `json:"respRaw,omitempty"`

	// OriginSeq is the history row this came from, for "view in History". It may
	// have been evicted; nothing depends on it resolving.
	OriginSeq int `json:"originSeq,omitempty"`

	// Setup marks a step the generator must not mutate — a login, an
	// add-to-cart. Because it is never omitted, moved or repeated, it survives
	// at its recorded position in every variant and so re-runs before each one,
	// which needs no prefix machinery and is what makes a stateful chain
	// testable: otherwise every variant after the first runs against state the
	// previous variant consumed. Marking a step Setup also says the operator is
	// not interested in what skipping it proves.
	Setup bool `json:"setup,omitempty"`

	// Edits are manual overrides, applied after binding spans so an operator can
	// override a bound value.
	Edits []httptools.Edit `json:"edits,omitempty"`
}

// Chain is an ordered workflow.
type Chain struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Steps     []Step    `json:"steps"`
	Bindings  []Binding `json:"bindings"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// GoalStepID is the step whose outcome decides a variant's verdict. Empty
	// means the last step, which is what an operator means by "did the checkout
	// go through".
	GoalStepID string `json:"goalStepId,omitempty"`
}

// Variant is one ordering to execute. Steps holds step IDs in execution order,
// with duplicates allowed.
type Variant struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	Label string   `json:"label"`
	Steps []string `json:"steps"`

	// Target names the step the mutation acted on, so a result row can say what
	// was done without re-deriving it from the ordering.
	Target string `json:"target,omitempty"`
}

// StepByID returns a step and its index, or false.
func (c *Chain) StepByID(id string) (Step, int, bool) {
	for i, s := range c.Steps {
		if s.ID == id {
			return s, i, true
		}
	}
	return Step{}, 0, false
}

// GoalStep resolves the goal, defaulting to the last step.
func (c *Chain) GoalStep() (Step, bool) {
	if len(c.Steps) == 0 {
		return Step{}, false
	}
	if c.GoalStepID != "" {
		if s, _, ok := c.StepByID(c.GoalStepID); ok {
			return s, true
		}
	}
	return c.Steps[len(c.Steps)-1], true
}

// BindingsInto returns the bindings a step consumes.
func (c *Chain) BindingsInto(stepID string) []Binding {
	var out []Binding
	for _, b := range c.Bindings {
		if b.ToStep == stepID {
			out = append(out, b)
		}
	}
	return out
}

// BindingsFrom returns the bindings a step produces.
func (c *Chain) BindingsFrom(stepID string) []Binding {
	var out []Binding
	for _, b := range c.Bindings {
		if b.FromStep == stepID {
			out = append(out, b)
		}
	}
	return out
}

// Clone returns a deep copy. The store hands these out so a caller editing a
// chain cannot mutate the live one behind everybody else's back.
func (c *Chain) Clone() *Chain {
	if c == nil {
		return nil
	}
	out := *c
	out.Steps = make([]Step, len(c.Steps))
	for i, s := range c.Steps {
		s.ReqRaw = append([]byte(nil), s.ReqRaw...)
		s.RespRaw = append([]byte(nil), s.RespRaw...)
		s.Edits = append([]httptools.Edit(nil), s.Edits...)
		out.Steps[i] = s
	}
	out.Bindings = make([]Binding, len(c.Bindings))
	for i, b := range c.Bindings {
		b.Spans = append([]Span(nil), b.Spans...)
		out.Bindings[i] = b
	}
	return &out
}

// Normalize materializes the collections that cross the API boundary.
//
// Every slice here is either omitempty or guaranteed non-nil, for the reason
// apispec.Spec.normalize gives: a field that is neither ships JSON null against a
// TypeScript type promising an array, and the first symptom is a map render
// crashing on someone's engagement.
func (c *Chain) Normalize() {
	if c.Steps == nil {
		c.Steps = []Step{}
	}
	if c.Bindings == nil {
		c.Bindings = []Binding{}
	}
	for i := range c.Bindings {
		if c.Bindings[i].Spans == nil {
			c.Bindings[i].Spans = []Span{}
		}
		if c.Bindings[i].OnMissing == "" {
			c.Bindings[i].OnMissing = MissingFail
		}
	}
}

// newID returns a short random identifier. Chains outlive a process and are
// merged across machines through project files, so their ids cannot be
// positional the way step and binding ids are.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice; a time-derived fallback keeps
		// this total rather than making every caller handle an error that
		// cannot happen.
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000")))
	}
	return hex.EncodeToString(b[:])
}
