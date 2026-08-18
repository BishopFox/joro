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

// Limits bound one run. Every field has a default and a ceiling; a zero field takes
// the default, and a field over the ceiling is clamped down to it. Clamping rather
// than rejecting is deliberate: these arrive from a caller that may be a language
// model, and the useful response to "timeoutMs: 600000" is a 60-second run, not an
// argument error that costs a turn.
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
}

// Defaults and ceilings for Limits, plus the source-size cap.
const (
	DefaultTimeout = 25 * time.Second
	MaxTimeout     = 60 * time.Second

	DefaultMemoryBytes int64 = 64 << 20
	MaxMemoryBytes     int64 = 256 << 20

	DefaultMaxCalls = 100
	CeilMaxCalls    = 500

	DefaultMaxSendCalls = 25
	CeilMaxSendCalls    = 100

	DefaultMaxLogBytes = 256 << 10
	CeilMaxLogBytes    = 1 << 20

	DefaultMaxResultBytes = 128 << 10
	CeilMaxResultBytes    = 1 << 20

	DefaultMaxCallInputBytes = 2 << 20
	CeilMaxCallInputBytes    = 8 << 20

	DefaultMaxCallOutputBytes = 8 << 20
	CeilMaxCallOutputBytes    = 32 << 20

	// MaxSourceBytes bounds the program itself. Well above anything hand-written or
	// generated, and far below a bundled dependency tree — which is a Phase C
	// concern and will want its own budget.
	MaxSourceBytes = 256 << 10
)

// Normalize fills zero fields with defaults and clamps everything to its ceiling.
func (l Limits) Normalize() Limits {
	l.Timeout = clampDur(l.Timeout, DefaultTimeout, MaxTimeout)
	l.MemoryBytes = clamp64(l.MemoryBytes, DefaultMemoryBytes, MaxMemoryBytes)
	l.MaxCalls = clampInt(l.MaxCalls, DefaultMaxCalls, CeilMaxCalls)
	l.MaxSendCalls = clampInt(l.MaxSendCalls, DefaultMaxSendCalls, CeilMaxSendCalls)
	l.MaxLogBytes = clampInt(l.MaxLogBytes, DefaultMaxLogBytes, CeilMaxLogBytes)
	l.MaxResultBytes = clampInt(l.MaxResultBytes, DefaultMaxResultBytes, CeilMaxResultBytes)
	l.MaxCallInputBytes = clampInt(l.MaxCallInputBytes, DefaultMaxCallInputBytes, CeilMaxCallInputBytes)
	l.MaxCallOutputBytes = clampInt(l.MaxCallOutputBytes, DefaultMaxCallOutputBytes, CeilMaxCallOutputBytes)
	return l
}

func clampDur(v, def, max time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return min(v, max)
}

func clamp64(v, def, max int64) int64 {
	if v <= 0 {
		return def
	}
	return min(v, max)
}

func clampInt(v, def, max int) int {
	if v <= 0 {
		return def
	}
	return min(v, max)
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

// maxStorageOps bounds joro.storage calls per run. A fixed constant rather than a
// configurable limit: it exists to stop a loop from hammering the pipe, not to express an
// operator's policy, and the wall clock already bounds the run itself.
const maxStorageOps = 1000

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
