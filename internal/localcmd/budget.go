package localcmd

import "time"

// The command budget is a separate policy from the script budget, not a reuse of it.
//
// jsruntime.Budget carries maxCalls, maxSendCalls and storageOps, none of which mean
// anything to a subprocess, and has no field for the two that matter most here — how
// much output Joro will hold and how much scratch it will keep. Folding one into the
// other would give the operator a form where half the fields are inert, and would put
// command-shaped values in a package whose whole claim is that it is JavaScript-only.
//
// # There is no memory field, and that is not an omission
//
// jsruntime needs one because a script shares Joro's heap: goja has no allocation
// ceiling, so a runaway script would be reclaimed by taking the process that holds the
// engagement's captured traffic. Building a worker process is how that package buys the
// property that a blowup costs the worker instead of the proxy.
//
// A command already has that property. It is a separate process by construction, so an
// allocation without bound is reclaimed at the command's expense and Joro survives it —
// the same containment, obtained for free. Adding a ceiling anyway would mean a resource
// limit that works on Linux, has no portable equivalent on macOS, and none at all on
// Windows: a field presented as enforcement on the platform where it is not.
//
// The shapes are otherwise deliberately parallel. Defaults, maxima, a host half, and a
// BudgetSpec table that carries each field's rationale beside its constant — so the
// operator's form is generated from the specs rather than restated in the frontend, and
// what the UI explains cannot drift from what this package enforces.

// The numbers Joro ships. Each field has two: the default a run gets when nobody said
// otherwise, and the maximum a run may ask for when the operator has named none.
//
// Stock maxima are not a bound on the operator, they are what applies in their absence.
// The only real ceilings are the structural ones below, each tied to a number elsewhere
// that cannot move at runtime.
const (
	// DefaultTimeout is longer than a script's 25 seconds because the tools this
	// exists for are slower: a scanner or a fetch against a live target is measured in
	// tens of seconds even when nothing is wrong.
	DefaultTimeout = 60 * time.Second

	DefaultMaxStdoutBytes = 256 << 10
	StockMaxStdoutBytes   = 4 << 20

	DefaultMaxStderrBytes = 64 << 10
	StockMaxStderrBytes   = 1 << 20

	DefaultMaxArtifactBytes int64 = 16 << 20
	StockMaxArtifactBytes   int64 = 256 << 20

	// DefaultMaxInlineInputBytes is what {{INPUT}} may put into argv when nobody said
	// otherwise. Generous enough for a request, which is the case inline input exists
	// for, and short of a response body, which is the case that should be piped.
	//
	// There is no "off" value, deliberately. Every other field here reads zero as
	// "unset, take the default", and one field where zero means something else would be
	// a trap; the coarse switch already exists and is --automation-commands. Lowering
	// this is how an operator narrows what can appear in ps.
	DefaultMaxInlineInputBytes = 64 << 10
)

// The structural ceilings: the figures an operator cannot raise, each because something
// outside this budget is fixed against it. Every one is reported to the UI with its
// reason, so a field is never presented as free when it is not.
const (
	// CapTimeout bounds a run because a run is the synchronous body of
	// POST /api/v1/automation/runs and the browser client gives up at 630 seconds. A
	// command permitted to outlive that would be killed by a client timeout instead of
	// reporting a termination reason, which is the one outcome worth preventing —
	// the operator would see a network error where a timeout belongs.
	CapTimeout = 10 * time.Minute

	// CapConcurrentRuns bounds overlapping command runs. Low, and lower than the
	// script ceiling, because the cost is different in kind: a script run is bounded by
	// a heap limit inside a process Joro controls, while each command run is a whole
	// process with its own memory ceiling and its own network activity.
	CapConcurrentRuns = 4

	// CapScratchRuns is the run log's own size. Keeping a scratch directory for a run
	// that has already fallen off the log leaves files on disk that nothing in the UI
	// can reach, which is a leak rather than a retention policy.
	CapScratchRuns = 50
)

// Defaults for the host half of the budget: limits an operator sets once for this Joro
// rather than per run, and which nothing may ask to change.
const (
	// DefaultConcurrentRuns is one. A command automation firing on captured traffic is
	// the case that matters, and serializing it is what keeps a burst of requests from
	// becoming a burst of processes.
	DefaultConcurrentRuns = 1

	// DefaultScratchRuns is how many runs keep their scratch directory, newest first.
	DefaultScratchRuns = 10
)

// Budget is the operator-facing and wire form of Limits: the same figures in the units a
// manifest declares and a form edits.
type Budget struct {
	TimeoutMs           int `json:"timeoutMs,omitempty"`
	MaxStdoutBytes      int `json:"maxStdoutBytes,omitempty"`
	MaxStderrBytes      int `json:"maxStderrBytes,omitempty"`
	MaxArtifactBytes    int `json:"maxArtifactBytes,omitempty"`
	MaxInlineInputBytes int `json:"maxInlineInputBytes,omitempty"`
}

// Limits converts to the runtime's own units. Not normalized: a zero stays a zero, so a
// caller can still tell "unspecified" from a real value.
func (b Budget) Limits() Limits {
	return Limits{
		Timeout:             time.Duration(b.TimeoutMs) * time.Millisecond,
		MaxStdoutBytes:      b.MaxStdoutBytes,
		MaxStderrBytes:      b.MaxStderrBytes,
		MaxArtifactBytes:    int64(b.MaxArtifactBytes),
		MaxInlineInputBytes: b.MaxInlineInputBytes,
	}
}

// Budget projects Limits back into operator units.
func (l Limits) Budget() Budget {
	return Budget{
		TimeoutMs:           int(l.Timeout / time.Millisecond),
		MaxStdoutBytes:      l.MaxStdoutBytes,
		MaxStderrBytes:      l.MaxStderrBytes,
		MaxArtifactBytes:    int(l.MaxArtifactBytes),
		MaxInlineInputBytes: l.MaxInlineInputBytes,
	}
}

// Value reports one field by its BudgetSpec key, and whether the key is known.
//
// Paired with BudgetSpecs so a caller can validate the whole budget without keeping a
// second list of fields: a sixth field added above without a case here fails loudly at
// its validator rather than reading as zero and passing unchecked.
func (b Budget) Value(key string) (int, bool) {
	switch key {
	case "timeoutMs":
		return b.TimeoutMs, true
	case "maxStdoutBytes":
		return b.MaxStdoutBytes, true
	case "maxStderrBytes":
		return b.MaxStderrBytes, true
	case "maxArtifactBytes":
		return b.MaxArtifactBytes, true
	case "maxInlineInputBytes":
		return b.MaxInlineInputBytes, true
	}
	return 0, false
}

// HostBudget is the half of the policy that is a property of this Joro rather than of one
// run.
type HostBudget struct {
	ConcurrentRuns int `json:"concurrentRuns,omitempty"`
	ScratchRuns    int `json:"scratchRuns,omitempty"`
}

// Resolved fills each unset field with its shipped default and holds every field to its
// ceiling, so a caller can use the result without checking anything.
func (h HostBudget) Resolved() HostBudget {
	return HostBudget{
		ConcurrentRuns: clamp(h.ConcurrentRuns, DefaultConcurrentRuns, CapConcurrentRuns),
		ScratchRuns:    clamp(h.ScratchRuns, DefaultScratchRuns, CapScratchRuns),
	}
}

// Value reports one field by its spec key, paired with HostSpecs for the same reason
// Budget.Value is paired with BudgetSpecs.
func (h HostBudget) Value(key string) (int, bool) {
	switch key {
	case "concurrentRuns":
		return h.ConcurrentRuns, true
	case "scratchRuns":
		return h.ScratchRuns, true
	}
	return 0, false
}

// Policy is everything the operator sets about command runs: what a run gets by default,
// the most it may ask for, and the host limits that are neither requestable nor
// declarable.
type Policy struct {
	Defaults Budget     `json:"defaults,omitzero"`
	Maxima   Budget     `json:"maxima,omitzero"`
	Host     HostBudget `json:"host,omitzero"`
}

// Normalize resolves a request against no policy at all: Joro's own defaults and stock
// maxima. It is what a caller with no operator policy in hand gets.
func (l Limits) Normalize() Limits { return l.NormalizeWith(Policy{}) }

// NormalizeWith resolves a request against the operator's policy, clamping each field
// between what they said a run gets and the most one may ask for.
func (l Limits) NormalizeWith(p Policy) Limits {
	lo, hi := boundsLimits(p)

	l.Timeout = clampDuration(l.Timeout, lo.Timeout, hi.Timeout)
	l.MaxStdoutBytes = clamp(l.MaxStdoutBytes, lo.MaxStdoutBytes, hi.MaxStdoutBytes)
	l.MaxStderrBytes = clamp(l.MaxStderrBytes, lo.MaxStderrBytes, hi.MaxStderrBytes)
	l.MaxArtifactBytes = clamp(l.MaxArtifactBytes, lo.MaxArtifactBytes, hi.MaxArtifactBytes)
	l.MaxInlineInputBytes = clamp(l.MaxInlineInputBytes, lo.MaxInlineInputBytes, hi.MaxInlineInputBytes)
	return l
}

// boundsLimits is the one per-field table of what a run's default and maximum resolve to
// under a policy. Every other function here reads it rather than restating the pairs.
func boundsLimits(p Policy) (lo, hi Limits) {
	d, m := p.Defaults, p.Maxima

	loT, hiT := boundsDuration(
		time.Duration(d.TimeoutMs)*time.Millisecond,
		time.Duration(m.TimeoutMs)*time.Millisecond,
		DefaultTimeout, CapTimeout, CapTimeout)
	lo.Timeout, hi.Timeout = loT, hiT

	lo.MaxStdoutBytes, hi.MaxStdoutBytes = bounds(
		d.MaxStdoutBytes, m.MaxStdoutBytes,
		DefaultMaxStdoutBytes, StockMaxStdoutBytes, 0)

	lo.MaxStderrBytes, hi.MaxStderrBytes = bounds(
		d.MaxStderrBytes, m.MaxStderrBytes,
		DefaultMaxStderrBytes, StockMaxStderrBytes, 0)

	lo.MaxArtifactBytes, hi.MaxArtifactBytes = bounds(
		int64(d.MaxArtifactBytes), int64(m.MaxArtifactBytes),
		DefaultMaxArtifactBytes, StockMaxArtifactBytes, 0)

	// The only per-run field with a structural ceiling as well as a stock maximum, and
	// the stock maximum is that ceiling: past it the platform refuses the exec, so there
	// is nothing above it for an operator to ask for.
	lo.MaxInlineInputBytes, hi.MaxInlineInputBytes = bounds(
		d.MaxInlineInputBytes, m.MaxInlineInputBytes,
		DefaultMaxInlineInputBytes, CapInlineInputBytes, CapInlineInputBytes)
	return lo, hi
}

// bounds resolves one field's default and maximum.
//
// The two rules, which are the same ones jsruntime states and must stay the same so an
// operator learns one behavior for both budgets:
//
// Joro's stock maximum never holds the operator's own default down — an operator who
// sets a default of 2 GB and names no maximum has said what a run gets, and answering
// 4 GB-or-ours would be the setting quietly not taking. And an operator maximum below
// their own default wins, because a maximum is the harder statement.
func bounds[T int | int64](opDef, opMax, def, stockMax, hard T) (lo, hi T) {
	lo = def
	if opDef > 0 {
		lo = opDef
	}
	switch {
	case opMax > 0:
		hi = opMax
	case lo > stockMax:
		hi = lo
	default:
		hi = stockMax
	}
	if hard > 0 && hi > hard {
		hi = hard
	}
	if lo > hi {
		lo = hi
	}
	return lo, hi
}

// boundsDuration is bounds for a time.Duration, which is an int64 but not assignable
// from one through the constraint.
func boundsDuration(opDef, opMax, def, stockMax, hard time.Duration) (lo, hi time.Duration) {
	l, h := bounds(int64(opDef), int64(opMax), int64(def), int64(stockMax), int64(hard))
	return time.Duration(l), time.Duration(h)
}

// Bounds reports what a run's default and maximum actually resolve to under this policy.
// The UI shows both, so a field never displays Joro's stock figure as the maximum when
// the operator's own default has raised it past that.
func (p Policy) Bounds() (defaults, maxima Budget) {
	lo, hi := boundsLimits(p)
	return lo.Budget(), hi.Budget()
}

// DefaultBudget and StockMaxima report this package's own numbers in operator units, so
// the UI can state them without a second copy of the table.
func DefaultBudget() Budget { return Limits{}.Normalize().Budget() }

// StockMaxima carries no TimeoutMs: the wall-clock maximum is CapTimeout rather than a
// stock figure below it, and the spec reports that as a Cap instead.
func StockMaxima() Budget {
	return Budget{
		MaxStdoutBytes:   StockMaxStdoutBytes,
		MaxStderrBytes:   StockMaxStderrBytes,
		MaxArtifactBytes: int(StockMaxArtifactBytes),

		// No MaxInlineInputBytes, for the same reason there is no TimeoutMs: its
		// ceiling is structural rather than a stock figure below one, and the spec
		// reports that as a Cap.
	}
}

// BudgetSpec documents one configurable field for the operator.
//
// Field-for-field identical to jsruntime.BudgetSpec, deliberately: the frontend renders
// both budgets with one component, and a second shape would mean a second component.
type BudgetSpec struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Unit   string `json:"unit"`
	Factor int    `json:"factor"`

	Default    int `json:"default"`
	DefaultMax int `json:"defaultMax,omitempty"`

	Cap         int    `json:"cap,omitempty"`
	CapReason   string `json:"capReason,omitempty"`
	Description string `json:"description"`
}

// BudgetSpecs describes the per-run fields, in the order they should be read: how long,
// what Joro keeps of the result, then what it will put in the command line.
func BudgetSpecs() []BudgetSpec {
	def, stock := DefaultBudget(), StockMaxima()
	return []BudgetSpec{
		// Entered in seconds, stored in milliseconds, because a manifest declares
		// milliseconds and the two have to be the same number.
		{Key: "timeoutMs", Label: "Wall clock", Unit: "seconds", Factor: 1000,
			Default:   def.TimeoutMs / 1000,
			Cap:       int(CapTimeout / time.Second),
			CapReason: "a run is the synchronous body of one API request, and the browser gives up at 630 seconds",
			Description: "How long a command may run before its process group is killed. Whatever it wrote " +
				"before that is still reported, so a timeout is informative rather than empty."},
		{Key: "maxStdoutBytes", Label: "Output kept", Unit: "KB", Factor: 1 << 10,
			Default: def.MaxStdoutBytes >> 10, DefaultMax: stock.MaxStdoutBytes >> 10,
			Description: "How much of stdout Joro holds. A command that exceeds it is stopped rather than " +
				"truncated, because output cut off mid-stream is not a complete answer and reporting " +
				"it as one would be worse than saying so."},
		{Key: "maxStderrBytes", Label: "Errors kept", Unit: "KB", Factor: 1 << 10,
			Default: def.MaxStderrBytes >> 10, DefaultMax: stock.MaxStderrBytes >> 10,
			Description: "How much of stderr is kept as the run's log. Over this the log truncates rather " +
				"than the run failing, so a chatty tool costs a note and not the result."},
		{Key: "maxArtifactBytes", Label: "Artifacts kept", Unit: "MB", Factor: 1 << 20,
			Default: def.MaxArtifactBytes >> 20, DefaultMax: stock.MaxArtifactBytes >> 20,
			Description: "How much the run's scratch directory may hold when Joro collects what the " +
				"command wrote. Files past this are listed but not retained, which is the failure " +
				"mode a scanner writing a report directory needs."},
		{Key: "maxInlineInputBytes", Label: "Inline input", Unit: "KB", Factor: 1 << 10,
			Default:   def.MaxInlineInputBytes >> 10,
			Cap:       CapInlineInputBytes >> 10,
			CapReason: "past this the operating system refuses to start the process at all, and reports nothing about which argument was at fault",
			Description: "How much of the input {{INPUT}} may put into an argument. Bytes in the command " +
				"line are readable by other processes on this machine, where bytes on standard input " +
				"are not, so this is the one budget that bounds exposure and not just size. Over it " +
				"the run is refused rather than truncated, and says to pipe the input instead."},
	}
}

// HostSpecs describes the two fields that belong to this Joro rather than to one run.
// They have no DefaultMax, because nothing can ask for another value: the operator's
// number is the limit.
func HostSpecs() []BudgetSpec {
	return []BudgetSpec{
		{Key: "concurrentRuns", Label: "Concurrent commands", Unit: "runs", Factor: 1,
			Default:   DefaultConcurrentRuns,
			Cap:       CapConcurrentRuns,
			CapReason: "each command is a separate process with its own memory ceiling, so overlapping runs multiply against the machine rather than against Joro's heap",
			Description: "How many commands may run at once. A run beyond this is refused rather than " +
				"queued, so a trigger firing on traffic paces itself instead of accumulating processes."},
		{Key: "scratchRuns", Label: "Scratch kept", Unit: "runs", Factor: 1,
			Default:   DefaultScratchRuns,
			Cap:       CapScratchRuns,
			CapReason: "the run log holds fifty runs, and scratch for a run that has fallen off it is unreachable from the UI",
			Description: "How many runs keep the working directory their command wrote into, newest first. " +
				"Older ones are removed with their artifacts."},
	}
}

// clamp reads a non-positive value as "take the default" and holds a positive one to the
// cap. Zero cap means uncapped.
func clamp[T int | int64](v, def, cap T) T {
	if v <= 0 {
		v = def
	}
	if cap > 0 && v > cap {
		v = cap
	}
	return v
}

func clampDuration(v, def, cap time.Duration) time.Duration {
	return time.Duration(clamp(int64(v), int64(def), int64(cap)))
}
