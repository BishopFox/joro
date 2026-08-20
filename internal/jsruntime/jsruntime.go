// Package jsruntime executes one JavaScript program under hard limits.
//
// It imports nothing from the rest of Joro, and that is the point. The runtime is
// handed a HostBridge whose only method takes a capability ID and a blob of JSON, so
// there is no field on any type in this package through which a script could reach a
// capture store, a token file, or an HTTP client. The bridge implementation lives
// elsewhere and is the only thing that knows what a capability is.
//
// Two Runtime implementations ship here:
//
//   - VM runs goja in the calling process. Fast, but a script sharing the Go heap can
//     allocate until the operating system kills that process.
//   - WorkerRuntime re-execs a host binary in worker mode and speaks to it over pipes.
//     A run is then terminated by killing a process rather than by asking a VM to
//     stop, and an allocation blowup takes the worker instead of the proxy.
//
// Joro uses WorkerRuntime. VM exists because the worker needs it: the child process
// calls it with a bridge that forwards over the pipe. Keeping both behind one
// interface is also what lets the untrusted-execution tier be replaced later without
// touching the SDK surface or any script anyone has written.
//
// # What the sandbox is, and is not
//
// A script can affect the outside world only by calling a capability. goja's default
// global object holds ECMAScript built-ins and nothing else — no process, no require,
// no fetch, no timers — so there is no ambient authority to take away, only a bridge
// to add. Combined with the worker boundary, a run cannot outlive its deadline,
// cannot exhaust the proxy's memory, and cannot reach the filesystem or a socket.
//
// It is not a defense against a deliberate engine exploit, and it does not need to
// be: any process running as the operator can already drive Joro's whole API. What
// this contains is the realistic failure — a generated script that loops forever,
// allocates without bound, or calls one capability ten thousand times.
package jsruntime

import (
	"context"
	"encoding/json"
	"time"
)

// Termination reasons. Every run ends with exactly one, and the operator sees it
// verbatim, so they are phrased as outcomes rather than error classes.
const (
	ReasonSuccess = "success"
	// ReasonException covers a throw the script did not catch, including one
	// originating from a denied capability call that it chose not to handle.
	ReasonException = "script exception"
	ReasonTimeout   = "timeout"
	// ReasonMemoryLimit means the heap ceiling was hit and the VM was interrupted.
	// It is distinct from ReasonWorkerLost, which is what an actual out-of-memory
	// kill looks like from the parent.
	ReasonMemoryLimit = "memory limit"
	ReasonBudget      = "sdk budget exceeded"
	ReasonCancelled   = "cancelled"
	// ReasonDenied means the run ended on an uncaught capability denial. It is
	// reported separately from a plain exception because the fix is a grant or a
	// scope rule, not a change to the script.
	ReasonDenied = "capability denied"
	// ReasonRuntimeFailure is ours, not the script's: a compile failure, an
	// unusable entry point, a result that will not serialize.
	ReasonRuntimeFailure = "runtime failure"
	// ReasonWorkerLost means the worker process died without reporting. The usual
	// cause is the operating system reclaiming it for memory.
	ReasonWorkerLost = "worker lost"
)

// Limits bound one run. A zero field takes the operator's default, and a field over
// their maximum is clamped down to it. Clamping rather than rejecting is deliberate:
// these arrive from a caller that may be a language model, and the useful response to
// "maxCalls: 9000" is a run at the maximum, not an argument error that costs a turn.
type Limits struct {
	Timeout     time.Duration `json:"timeout"`
	MemoryBytes int64         `json:"memoryBytes"`

	// MaxCalls bounds SDK calls of any kind; MaxSendCalls separately bounds the
	// subset that puts bytes on the wire. Two counters because the cost of a read
	// is context and the cost of a send is traffic against someone's target.
	MaxCalls     int `json:"maxCalls"`
	MaxSendCalls int `json:"maxSendCalls"`

	MaxLogBytes    int `json:"maxLogBytes"`
	MaxResultBytes int `json:"maxResultBytes"`

	// Cumulative bytes across every SDK call, in and out. A script that stays
	// inside MaxCalls can still drag megabytes through the bridge one call at a
	// time, and the parent has to hold each result in memory to forward it.
	MaxCallInputBytes  int `json:"maxCallInputBytes"`
	MaxCallOutputBytes int `json:"maxCallOutputBytes"`

	// MaxStorageOps and MaxSourceBytes come from the host half of the budget rather
	// than from anything a run or an author may request: one bounds how hard a loop
	// can hammer the host pipe, the other how large a program may be at all.
	MaxStorageOps  int `json:"maxStorageOps"`
	MaxSourceBytes int `json:"maxSourceBytes"`
}

// The numbers Joro ships. Each field has two: the default a run gets when nobody said
// otherwise, and the maximum a run may ask for when the *operator* has not set one.
//
// Stock maxima are not a bound on the operator. They are what applies in their absence,
// so an agent cannot ask for an unbounded run on a Joro nobody has configured. An
// operator may set any maximum they like; the only real ceilings are the structural ones
// below, each tied to a number somewhere else that cannot move at runtime.
const (
	// DefaultTimeout has no stock maximum beside it because CapTimeout serves as one:
	// the operator may hold a run below the cap but cannot raise past it, so the two
	// figures would be the same number. See boundsLimits.
	DefaultTimeout = 25 * time.Second

	DefaultMemoryBytes  int64 = 64 << 20
	StockMaxMemoryBytes int64 = 256 << 20

	DefaultMaxCalls = 100
	StockMaxCalls   = 500

	DefaultMaxSendCalls = 25
	StockMaxSendCalls   = 100

	DefaultMaxLogBytes = 256 << 10
	StockMaxLogBytes   = 1 << 20

	DefaultMaxResultBytes = 128 << 10
	StockMaxResultBytes   = 1 << 20

	// The cumulative byte budgets are not offered to the operator at all: they bound
	// what the host holds in memory while forwarding, which is Joro's concern rather
	// than a policy an engagement varies. Default and hard bound, therefore.
	DefaultMaxCallInputBytes = 2 << 20
	CapMaxCallInputBytes     = 8 << 20

	DefaultMaxCallOutputBytes = 8 << 20
	CapMaxCallOutputBytes     = 32 << 20
)

// The structural ceilings: the only figures here an operator cannot raise, each because
// something outside this budget is fixed against it. Every one of them is reported to the
// UI with its reason, so a field is never presented as free when it is not.
const (
	// CapTimeout bounds a run because the capability that exposes one to an agent
	// registers its own deadline before the registry is sealed, and that cannot change
	// while Joro is running. capreg derives that deadline from this.
	CapTimeout = 10 * time.Minute

	// CapSourceBytes bounds a program because the automation control plane caps the
	// request that carries it. internal/api derives that body limit from this.
	CapSourceBytes = 1 << 20

	// CapConcurrentRuns bounds overlapping runs because each holds up to two of the
	// capability registry's eight global concurrency slots: a fourth could take every
	// slot and starve the operator's own automation calls.
	CapConcurrentRuns = 3

	// AgentOutputCap is what an agent's log and result figures share, because the tool
	// result they travel in has one size and fails whole rather than truncating.
	// capreg derives that tool result cap from this.
	AgentOutputCap = 240 << 10
)

// Defaults and ceilings for the host half of the budget: limits an operator sets once
// for this Joro rather than per run, and which neither an author nor a caller may ask
// to change.
//
// Two of these are enforced outside this package — concurrent runs in the run manager,
// the agent output caps in the capability that exposes a run to an agent. They are
// declared here anyway, so the operator sees one budget with one form and one
// validator instead of three, and each field's spec names where it bites.
const (
	// DefaultStorageOps bounds joro.storage calls per run. It exists to stop a loop
	// hammering the host pipe, not to express a policy, which is why the default is
	// far above any real automation's use — and why the operator's number is final.
	DefaultStorageOps = 1000

	// DefaultSourceBytes: well above anything hand-written or generated, far below a
	// bundled dependency tree. Capped by CapSourceBytes.
	DefaultSourceBytes = 256 << 10

	// DefaultConcurrentRuns, capped by CapConcurrentRuns.
	DefaultConcurrentRuns = 2

	// What an agent gets back from a run. The pair shares AgentOutputCap, so each is
	// capped by it and the caller of SetScriptBudget checks their sum as well.
	DefaultAgentLogBytes    = 64 << 10
	DefaultAgentResultBytes = 96 << 10
)

// MaxSourceBytes is the shipped program-size limit, kept as the name callers already
// use for the default.
const MaxSourceBytes = DefaultSourceBytes

// Normalize resolves a request against no policy at all: Joro's own defaults and stock
// maxima. It is what a caller with no operator policy in hand gets.
func (l Limits) Normalize() Limits { return l.NormalizeWith(BudgetPolicy{}) }

// Fill supplies a default for any field left at zero and enforces the absolute caps, and
// deliberately does *not* apply the stock maxima.
//
// Those maxima bound what a caller may ask for, and that question is settled once, in the
// run manager, against the operator's policy. By the time Limits reaches this package the
// numbers are a resolved budget rather than a request — so re-applying a stock maximum
// here would silently lower a limit the operator raised, which is exactly what happened
// when the worker re-normalized a job the parent had already resolved. Every internal
// entry point therefore fills rather than normalizes.
func (l Limits) Fill() Limits {
	l.Timeout = clamp(l.Timeout, DefaultTimeout, CapTimeout)
	l.MemoryBytes = clamp(l.MemoryBytes, DefaultMemoryBytes, 0)
	l.MaxCalls = clamp(l.MaxCalls, DefaultMaxCalls, 0)
	l.MaxSendCalls = clamp(l.MaxSendCalls, DefaultMaxSendCalls, 0)
	l.MaxLogBytes = clamp(l.MaxLogBytes, DefaultMaxLogBytes, 0)
	l.MaxResultBytes = clamp(l.MaxResultBytes, DefaultMaxResultBytes, 0)
	l.MaxCallInputBytes = clamp(l.MaxCallInputBytes, DefaultMaxCallInputBytes, CapMaxCallInputBytes)
	l.MaxCallOutputBytes = clamp(l.MaxCallOutputBytes, DefaultMaxCallOutputBytes, CapMaxCallOutputBytes)
	l.MaxStorageOps = clamp(l.MaxStorageOps, DefaultStorageOps, 0)
	l.MaxSourceBytes = clamp(l.MaxSourceBytes, DefaultSourceBytes, CapSourceBytes)
	return l
}

// NormalizeWith resolves a requested budget against the operator's policy.
//
// Per field the operator sets two numbers, and they answer two different questions: the
// default is what a run that asks for nothing gets, and the maximum is the most a run may
// ask for. Either can be left unset, in which case this package's own number applies —
// so an unconfigured Joro behaves exactly as it did before there was a policy. A request
// over the maximum is clamped down rather than refused, for the reason Limits' own doc
// comment gives, and nothing here can exceed a shipped ceiling even from a hand-edited
// file.
func (l Limits) NormalizeWith(p BudgetPolicy) Limits {
	lo, hi := boundsLimits(p)
	l.Timeout = clamp(l.Timeout, lo.Timeout, hi.Timeout)
	l.MemoryBytes = clamp(l.MemoryBytes, lo.MemoryBytes, hi.MemoryBytes)
	l.MaxCalls = clamp(l.MaxCalls, lo.MaxCalls, hi.MaxCalls)
	l.MaxSendCalls = clamp(l.MaxSendCalls, lo.MaxSendCalls, hi.MaxSendCalls)
	l.MaxLogBytes = clamp(l.MaxLogBytes, lo.MaxLogBytes, hi.MaxLogBytes)
	l.MaxResultBytes = clamp(l.MaxResultBytes, lo.MaxResultBytes, hi.MaxResultBytes)

	// Not offered to the operator, so a plain default and a hard bound.
	l.MaxCallInputBytes = clamp(l.MaxCallInputBytes, DefaultMaxCallInputBytes, CapMaxCallInputBytes)
	l.MaxCallOutputBytes = clamp(l.MaxCallOutputBytes, DefaultMaxCallOutputBytes, CapMaxCallOutputBytes)

	// Host limits have no requestable side, so the operator's value is simply the
	// default here. Clamped rather than assigned because this runs a second time inside
	// the worker, which holds no policy: assigning would reset a limit the parent had
	// already resolved back to the shipped default.
	host := p.Host.Resolved()
	l.MaxStorageOps = clamp(l.MaxStorageOps, host.StorageOps, 0)
	l.MaxSourceBytes = clamp(l.MaxSourceBytes, host.SourceBytes, CapSourceBytes)
	return l
}

// boundsLimits is the one per-field table: what each field's default and maximum resolve
// to under a policy. NormalizeWith clamps a request between them and Bounds reports them,
// so a field's rule is written once and the two cannot drift.
func boundsLimits(p BudgetPolicy) (lo, hi Limits) {
	d, m := p.Defaults.Limits(), p.Maxima.Limits()

	// Wall clock is the one field whose stock maximum *is* its cap. The operator sets a
	// maximum here like anywhere else and it is honored below the ceiling — but a blank
	// box then means 600s rather than some third number, so the greyed figure in the box
	// and the ceiling printed under the row are the same value and cannot read as
	// contradicting each other.
	lo.Timeout, hi.Timeout = bounds(d.Timeout, m.Timeout, DefaultTimeout, CapTimeout, CapTimeout)

	lo.MemoryBytes, hi.MemoryBytes = bounds(d.MemoryBytes, m.MemoryBytes, DefaultMemoryBytes, StockMaxMemoryBytes, 0)
	lo.MaxCalls, hi.MaxCalls = bounds(d.MaxCalls, m.MaxCalls, DefaultMaxCalls, StockMaxCalls, 0)
	lo.MaxSendCalls, hi.MaxSendCalls = bounds(d.MaxSendCalls, m.MaxSendCalls, DefaultMaxSendCalls, StockMaxSendCalls, 0)
	lo.MaxLogBytes, hi.MaxLogBytes = bounds(d.MaxLogBytes, m.MaxLogBytes, DefaultMaxLogBytes, StockMaxLogBytes, 0)
	lo.MaxResultBytes, hi.MaxResultBytes = bounds(d.MaxResultBytes, m.MaxResultBytes, DefaultMaxResultBytes, StockMaxResultBytes, 0)
	return lo, hi
}

// budgetNum is the three field types in Limits: int, int64 and time.Duration.
type budgetNum interface{ ~int | ~int64 }

// clamp reads a zero as "unspecified" and takes def; anything else is held to cap, where
// a cap of zero means there is none.
func clamp[T budgetNum](v, def, cap T) T {
	if v <= 0 {
		v = def
	}
	if cap > 0 && v > cap {
		return cap
	}
	return v
}

// bounds reports what one field's default and maximum resolve to under a policy.
//
// opDef and opMax are the operator's pair, either of which may be unset; def and stockMax
// are what Joro ships in their absence; cap is the structural ceiling, or zero where the
// operator's number is final.
//
// Two rules worth stating. Joro's stock maximum never holds the operator's own default
// down: an operator who sets a default of 2000 MB and names no maximum has said what a run
// gets, and answering 256 because that is our number would be the setting quietly not
// taking. And an operator maximum below their own default wins, because a maximum is the
// harder statement — though the control plane rejects that pair rather than storing it, so
// this only arises from a hand-edited file.
func bounds[T budgetNum](opDef, opMax, def, stockMax, cap T) (lo, hi T) {
	lo = clamp(opDef, def, cap)
	hi = clamp(opMax, max(stockMax, lo), cap)
	return min(lo, hi), hi
}

// resolve applies one field's rule to a requested value.
func resolve[T budgetNum](v, opDef, opMax, def, stockMax, cap T) T {
	lo, hi := bounds(opDef, opMax, def, stockMax, cap)
	return clamp(v, lo, hi)
}

// Budget is Limits in the units an operator reads and a config file stores: whole
// milliseconds and megabytes rather than a time.Duration and a byte count. A zero field
// means "unspecified" rather than zero of anything, which is what lets one shape serve
// an author's request, the operator's global, and the wire.
type Budget struct {
	TimeoutMs      int `json:"timeoutMs,omitempty"`
	MemoryMB       int `json:"memoryMb,omitempty"`
	MaxCalls       int `json:"maxCalls,omitempty"`
	MaxSendCalls   int `json:"maxSendCalls,omitempty"`
	MaxLogBytes    int `json:"maxLogBytes,omitempty"`
	MaxResultBytes int `json:"maxResultBytes,omitempty"`
}

// Limits converts to the runtime's own units. Not normalized: a zero stays a zero, so a
// caller can still tell "unspecified" from a real value.
func (b Budget) Limits() Limits {
	return Limits{
		Timeout:        time.Duration(b.TimeoutMs) * time.Millisecond,
		MemoryBytes:    int64(b.MemoryMB) << 20,
		MaxCalls:       b.MaxCalls,
		MaxSendCalls:   b.MaxSendCalls,
		MaxLogBytes:    b.MaxLogBytes,
		MaxResultBytes: b.MaxResultBytes,
	}
}

// Value reports one field by its BudgetSpec key, and whether the key is known.
//
// Paired with BudgetSpecs so a caller can validate the whole budget without keeping a
// second list of fields: a seventh field added above without a case here fails loudly at
// its validator rather than reading as zero and passing unchecked.
func (b Budget) Value(key string) (int, bool) {
	switch key {
	case "timeoutMs":
		return b.TimeoutMs, true
	case "memoryMb":
		return b.MemoryMB, true
	case "maxCalls":
		return b.MaxCalls, true
	case "maxSendCalls":
		return b.MaxSendCalls, true
	case "maxLogBytes":
		return b.MaxLogBytes, true
	case "maxResultBytes":
		return b.MaxResultBytes, true
	}
	return 0, false
}

// Budget projects Limits back into operator units. Memory rounds up, because reporting a
// ceiling lower than the one being enforced would read as a bug in the enforcement.
func (l Limits) Budget() Budget {
	return Budget{
		TimeoutMs:      int(l.Timeout / time.Millisecond),
		MemoryMB:       int((l.MemoryBytes + (1 << 20) - 1) >> 20),
		MaxCalls:       l.MaxCalls,
		MaxSendCalls:   l.MaxSendCalls,
		MaxLogBytes:    l.MaxLogBytes,
		MaxResultBytes: l.MaxResultBytes,
	}
}

// BudgetPolicy is everything the operator sets about runs: what a run gets by default,
// the most it may ask for, and the host limits that are neither requestable nor
// declarable.
//
// One struct because it is one form, one stored object and one validator. Persisted in
// ~/.joro/automation.json; see internal/automation.
type BudgetPolicy struct {
	Defaults Budget     `json:"defaults,omitzero"`
	Maxima   Budget     `json:"maxima,omitzero"`
	Host     HostBudget `json:"host,omitzero"`
}

// HostBudget is the half of the policy that is a property of this Joro rather than of one
// run: how hard a script may hammer storage, how large a program may be, how many runs
// may overlap, and how much of a run's output an agent gets back.
type HostBudget struct {
	StorageOps       int `json:"storageOps,omitempty"`
	SourceBytes      int `json:"sourceBytes,omitempty"`
	ConcurrentRuns   int `json:"concurrentRuns,omitempty"`
	AgentLogBytes    int `json:"agentLogBytes,omitempty"`
	AgentResultBytes int `json:"agentResultBytes,omitempty"`
}

// Resolved fills each unset field with its shipped default and holds every field to its
// ceiling, so a caller can use the result without checking anything.
func (h HostBudget) Resolved() HostBudget {
	return HostBudget{
		StorageOps:       clamp(h.StorageOps, DefaultStorageOps, 0),
		SourceBytes:      clamp(h.SourceBytes, DefaultSourceBytes, CapSourceBytes),
		ConcurrentRuns:   clamp(h.ConcurrentRuns, DefaultConcurrentRuns, CapConcurrentRuns),
		AgentLogBytes:    clamp(h.AgentLogBytes, DefaultAgentLogBytes, AgentOutputCap),
		AgentResultBytes: clamp(h.AgentResultBytes, DefaultAgentResultBytes, AgentOutputCap),
	}
}

// Value reports one field by its spec key, paired with HostSpecs for the same reason
// Budget.Value is paired with BudgetSpecs.
func (h HostBudget) Value(key string) (int, bool) {
	switch key {
	case "storageOps":
		return h.StorageOps, true
	case "sourceBytes":
		return h.SourceBytes, true
	case "concurrentRuns":
		return h.ConcurrentRuns, true
	case "agentLogBytes":
		return h.AgentLogBytes, true
	case "agentResultBytes":
		return h.AgentResultBytes, true
	}
	return 0, false
}

// Bounds reports what a run's default and maximum actually resolve to under this policy.
//
// The UI shows both, so a field never displays Joro's stock figure as the maximum when the
// operator's own default has raised it past that.
func (p BudgetPolicy) Bounds() (defaults, maxima Budget) {
	lo, hi := boundsLimits(p)
	return lo.Budget(), hi.Budget()
}

// DefaultBudget and StockMaxima report this package's own numbers in operator units, so
// the UI can state them without a second copy of the table.
func DefaultBudget() Budget { return Limits{}.Normalize().Budget() }

// StockMaxima carries no TimeoutMs: the wall-clock maximum is CapTimeout rather than a
// figure that applies in the operator's absence, and BudgetSpecs reports it as a cap.
func StockMaxima() Budget {
	return Budget{
		// For wall clock the figure that applies in the operator's absence and the one
		// they cannot exceed are the same: there is no separate stock maximum.
		TimeoutMs:      int(CapTimeout / time.Millisecond),
		MemoryMB:       int(StockMaxMemoryBytes >> 20),
		MaxCalls:       StockMaxCalls,
		MaxSendCalls:   StockMaxSendCalls,
		MaxLogBytes:    StockMaxLogBytes,
		MaxResultBytes: StockMaxResultBytes,
	}
}

// BudgetSpec documents one configurable field for the operator.
//
// The rationale lives here beside the constants rather than in the frontend, so what the
// UI explains cannot drift from what the runtime enforces.
type BudgetSpec struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Unit  string `json:"unit"`
	// Factor converts the operator's unit to the stored one: a value entered as
	// seconds is stored as milliseconds with a factor of 1000. Every other figure on
	// this struct is already in the operator's unit; the field on Budget is not.
	Factor int `json:"factor"`
	// Default is what a run gets when nobody set one; DefaultMax is the most a run may
	// ask for while the operator has named no maximum. Both are Joro's own numbers, and
	// both are replaced outright by whatever the operator types.
	//
	// DefaultMax is absent only on a host spec, which has no requestable side and so no
	// maximum to speak of — one editable figure and, where it applies, a Cap.
	Default    int `json:"default"`
	DefaultMax int `json:"defaultMax,omitempty"`
	// Cap is the one figure the operator cannot exceed, and CapReason says what it is
	// fixed against. Zero means there is no cap and their number is final — which is
	// the case for most of these, so a field is never shown as free when it is not.
	Cap         int    `json:"cap,omitempty"`
	CapReason   string `json:"capReason,omitempty"`
	Description string `json:"description"`
}

// BudgetSpecs describes the six per-run fields, in the order they should be read: what a
// run may do, then how long it may take, then what it may return.
func BudgetSpecs() []BudgetSpec {
	def, stock := DefaultBudget(), StockMaxima()
	return []BudgetSpec{
		{Key: "maxCalls", Label: "SDK calls", Unit: "calls", Factor: 1,
			Default: def.MaxCalls, DefaultMax: stock.MaxCalls,
			Description: "Bounds SDK calls of any kind; the cost of a read is your context, and the default covers the multi-item sweep this tier exists for."},
		{Key: "maxSendCalls", Label: "Sending calls", Unit: "calls", Factor: 1,
			Default: def.MaxSendCalls, DefaultMax: stock.MaxSendCalls,
			Description: "Bounds the subset that puts bytes on a target, counted separately because the cost of a send is traffic against someone's systems."},
		// Entered in seconds. The stored field is milliseconds because that is what an
		// automation manifest declares, and the two have to be the same number.
		{Key: "timeoutMs", Label: "Wall clock", Unit: "seconds", Factor: 1000,
			Default:     def.TimeoutMs / 1000,
			DefaultMax:  stock.TimeoutMs / 1000,
			Cap:         int(CapTimeout / time.Second),
			CapReason:   "the deadline the script.run tool registers for itself, which is fixed when Joro starts",
			Description: "How long a run may take before its worker process is killed. A run that ends sooner costs nothing extra, so this is a bound rather than a budget to spend."},
		{Key: "memoryMb", Label: "Memory", Unit: "MB", Factor: 1,
			Default: def.MemoryMB, DefaultMax: stock.MemoryMB,
			Description: "Heap ceiling for the worker process; the engine has no allocation limit of its own and Joro holds captured traffic in memory, so a runaway must cost the worker rather than the proxy."},
		{Key: "maxLogBytes", Label: "Log output", Unit: "KB", Factor: 1 << 10,
			Default: def.MaxLogBytes >> 10, DefaultMax: stock.MaxLogBytes >> 10,
			Description: "How much console output is kept; over this the log truncates rather than the run failing, so a chatty loop costs a note and not the result."},
		{Key: "maxResultBytes", Label: "Result size", Unit: "KB", Factor: 1 << 10,
			Default: def.MaxResultBytes >> 10, DefaultMax: stock.MaxResultBytes >> 10,
			Description: "How large a value run() may return; over this the run fails rather than truncating, because truncated JSON would be mis-parsed silently."},
	}
}

// HostSpecs describes the five fields that belong to this Joro rather than to one run.
// They have no DefaultMax, because nothing can ask for another value: the operator's
// number is the limit.
func HostSpecs() []BudgetSpec {
	return []BudgetSpec{
		{Key: "concurrentRuns", Label: "Concurrent runs", Unit: "runs", Factor: 1,
			Default:     DefaultConcurrentRuns,
			Cap:         CapConcurrentRuns,
			CapReason:   "each run holds up to two of the capability registry's eight global slots, and the rest have to stay reachable",
			Description: "How many runs may execute at once. A run beyond this is refused rather than queued, so the caller learns to retry instead of waiting."},
		{Key: "storageOps", Label: "Storage operations", Unit: "ops", Factor: 1,
			Default:     DefaultStorageOps,
			Description: "How many joro.storage reads and writes one run may make. It stops a loop hammering the host pipe; the wall clock already bounds the run itself."},
		{Key: "sourceBytes", Label: "Program size", Unit: "KB", Factor: 1 << 10,
			Default:     DefaultSourceBytes >> 10,
			Cap:         CapSourceBytes >> 10,
			CapReason:   "the automation API caps the request that carries a program, and this has to stay inside it",
			Description: "How large an automation's code may be. Checked at install and again at run, since there is no module loader and a package is one bundled script."},
		{Key: "agentLogBytes", Label: "Agent log output", Unit: "KB", Factor: 1 << 10,
			Default:     DefaultAgentLogBytes >> 10,
			Cap:         AgentOutputCap >> 10,
			CapReason:   "an agent's whole tool result shares this size and fails whole rather than truncating, so the two agent figures share it too",
			Description: "How much of a run's log an agent gets back from script_run. Separate from the run's own log budget, which is what the operator reads in the run log."},
		{Key: "agentResultBytes", Label: "Agent result size", Unit: "KB", Factor: 1 << 10,
			Default:     DefaultAgentResultBytes >> 10,
			Cap:         AgentOutputCap >> 10,
			CapReason:   "shared with the agent log figure above; their sum is what has to fit",
			Description: "How much of a run's return value an agent gets back. Raise this and the log figure together only as far as the pair fits."},
	}
}

// Meta is the non-secret description of a run, handed to the script as ctx.run,
// ctx.automation and ctx.trigger.
//
// Nothing here may be a bearer token, a cookie, a filesystem path, or an internal Go
// identifier. A script's authority comes from the principal the host invokes with,
// never from a value it can read out of its own context — so there is no reason for
// anything sensitive to be in reach, and a script that could read one would leak it
// into its own return value or logs.
type Meta struct {
	RunID     string `json:"runId"`
	StartedAt string `json:"startedAt"`

	AutomationID      string `json:"automationId,omitempty"`
	AutomationVersion string `json:"automationVersion,omitempty"`

	TriggerType string `json:"triggerType"`

	// TriggerData is merged into ctx.trigger beside the type, so an event-driven run
	// can see what woke it. It carries references — a request seq, a finding id, a
	// campaign id — and never a resolved object: the script fetches detail through the
	// SDK, where its principal is enforced. Receiving an event is not permission to
	// read what the event is about.
	TriggerData json.RawMessage `json:"triggerData,omitempty"`
}

// Request is one program to run.
type Request struct {
	Source string          `json:"source"`
	Input  json.RawMessage `json:"input,omitempty"`
	Meta   Meta            `json:"meta"`
	Limits Limits          `json:"limits"`

	// SendCaps names the capability IDs that put bytes on the wire, so the runtime
	// can charge them against MaxSendCalls. The host supplies it rather than this
	// package carrying a list of Joro capability IDs that could fall out of step
	// with the registry — and passing it as data means the in-process and worker
	// paths share one mechanism instead of the worker having to bridge an interface.
	SendCaps []string `json:"sendCaps,omitempty"`
}

// LogLine is one captured console call.
type LogLine struct {
	At    string `json:"at"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Result is the outcome of a run. It is always returned, including on failure: a run
// that timed out still has logs, a call count, and whatever it managed to do, and
// those are exactly what the operator needs in order to understand it.
type Result struct {
	Reason string `json:"reason"`
	// Err carries the script's own error message when Reason is an exception, a
	// denial, or a runtime failure. Never a Go error string with a wrapped chain —
	// the audience is a person reading Activity or a model correcting its own code.
	Err string `json:"err,omitempty"`

	// Value is the JSON-marshalled return value of run(). Absent unless the run
	// succeeded.
	Value json.RawMessage `json:"value,omitempty"`

	Logs          []LogLine `json:"logs,omitempty"`
	LogsTruncated bool      `json:"logsTruncated,omitempty"`

	Calls     int `json:"calls"`
	SendCalls int `json:"sendCalls"`
	// StorageOps counts joro.storage calls. Tracked separately from Calls because
	// storage is not a capability invocation: it consumes no registry budget, engages
	// no scope guard, and writes no audit entry.
	StorageOps      int `json:"storageOps,omitempty"`
	CallInputBytes  int `json:"callInputBytes"`
	CallOutputBytes int `json:"callOutputBytes"`

	// Budget is what this run was actually held to, after the operator's global was
	// applied. Reported rather than left implicit because a count with nothing to read
	// it against explains nothing — and because a model that asked for more than it got
	// learns the real number here, which the static tool schema cannot tell it.
	Budget Budget `json:"budget"`

	DurationMs int64 `json:"durationMs"`
}

// OK reports whether the run completed normally.
func (r Result) OK() bool { return r.Reason == ReasonSuccess }

// HostBridge is everything a script can reach. One method, two JSON blobs.
//
// Deliberately not an interface with a method per subsystem: the whole authorization
// story is that a call is named by a capability ID and evaluated by the registry, and
// a bridge with a ReadHistory method would be a second place where that decision
// could be made differently.
type HostBridge interface {
	// Invoke runs one capability. args and the returned value are JSON. An error
	// becomes a JavaScript throw; a *CallError additionally carries a code the
	// script can branch on and tells the runtime whether the failure was a denial.
	Invoke(ctx context.Context, id string, args json.RawMessage) (json.RawMessage, error)
}

// StorageBridge is the per-automation key/value store, exposed to a script as
// joro.storage. Optional: a bridge that does not implement it makes joro.storage report
// that this run has no namespace, which is the honest answer for a one-shot script.
//
// This is the one part of the SDK that is not a capability, and the reason is that there
// is nothing to authorize. The namespace is bound by the host from the automation's own
// identity and is never an argument, so a script cannot name another automation's data;
// and storage reaches nothing — not a target, not the operator's configuration, not
// Joro's state. It is memory, not authority. Making it a capability would add a grant
// checkbox whose only possible answer is the one already implied by installing the
// automation.
//
// op is one of "get", "set", "delete", "keys".
type StorageBridge interface {
	Storage(ctx context.Context, op, key string, value json.RawMessage) (json.RawMessage, error)
}

// storageUnavailableMsg is reported by both the in-process VM and the worker's parent, so
// an operator sees one wording however the run was executed.
const storageUnavailableMsg = "joro.storage is available only to an installed automation: a " +
	"one-shot script has no namespace of its own. Return the value instead, or install this as " +
	"an automation"

// CallError is a capability failure the script can inspect. Code becomes err.code in
// JavaScript, so a script can retry on "busy" and give up on "forbidden".
type CallError struct {
	Code string
	Msg  string
	// Denied distinguishes an authorization refusal from a handler that ran and
	// failed. It changes the run's termination reason when the script does not
	// catch it, because a denial is fixed by a grant and a handler error is not.
	Denied bool
}

func (e *CallError) Error() string {
	if e.Msg == "" {
		return e.Code
	}
	if e.Code == "" {
		return e.Msg
	}
	return e.Code + ": " + e.Msg
}

// Runtime executes a program. Implementations must honor ctx cancellation by ending
// the run, not merely by returning: a Runtime that leaves a script executing after
// Run returns would let cancelled work keep calling capabilities.
type Runtime interface {
	Run(ctx context.Context, req Request, bridge HostBridge) (Result, error)
}
