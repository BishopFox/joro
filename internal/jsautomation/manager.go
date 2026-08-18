// Package jsautomation runs sandboxed JavaScript against Joro's capability registry.
//
// It owns three things the runtime deliberately does not: the principal a run acts as,
// the budget the run is held to, and the record of what it did. The runtime knows how to
// execute JavaScript and nothing about Joro; this package knows about Joro and nothing
// about JavaScript.
//
// The dependency shape is the interesting part. This package is handed an Invoker — the
// sealed capability registry behind a three-method interface — and never a service
// object. A script's reach is therefore exactly the registry's, evaluated call by call
// with the registry's own guard, limits and audit trail. There is no second
// authorization path to keep in step, and no host function that could grow one.
package jsautomation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/jsruntime"
)

// maxConcurrentRuns bounds how many scripts execute at once.
//
// Each active run occupies two of the registry's global concurrency slots: one for the
// outer capability, held for the run's whole duration, and one for whichever SDK call is
// in flight. Leaving this unbounded would let a handful of scripts consume every slot
// and starve the operator's other automation calls, which is the failure the global
// semaphore exists to prevent in the first place.
const maxConcurrentRuns = 2

// Invoker is the sealed capability registry, narrowed to what a script run needs.
// *capability.Registry satisfies it.
type Invoker interface {
	// Invoke applies the full guard: authorization, scope, limits, timeout, audit.
	Invoke(ctx context.Context, p capability.Principal, id string, args json.RawMessage) (capability.Result, error)
	// Get reports a capability's declaration, used to learn which IDs send traffic.
	Get(id string) (capability.Capability, bool)
	// Forget drops a token's rate bucket and concurrency counter. A run's synthetic
	// identity would otherwise accumulate one entry per run, forever.
	Forget(tokenID string)
}

// Deps is what the manager needs from the rest of Joro.
type Deps struct {
	// Registry is a getter because the registry is built after this manager exists:
	// the capability that starts a run needs the runner, and the runner needs the
	// sealed registry. The same lazy-getter shape Deps.BgCtx already uses in capreg.
	Registry func() Invoker

	// Runtime executes the program. In production this is a worker-process runtime,
	// so a run is terminated by killing a process rather than by asking a VM to stop.
	Runtime jsruntime.Runtime

	// Contexts holds the per-principal cookie jars. A run's jar is keyed on its
	// synthetic token ID, so a login in one SDK call authenticates later calls in the
	// same run and is dropped when the run ends — a session belongs to the run that
	// authenticated it.
	Contexts *httptools.Contexts

	// Store is the installed-automation directory; Storage is their key/value state.
	// Both nil-tolerated: without a Store there are no installed automations and only
	// one-shot runs work, which is exactly phase B's behavior.
	Store   *Store
	Storage *Storage
}

// Manager runs scripts and remembers what they did.
type Manager struct {
	deps Deps
	sem  chan struct{}
	runs *RunLog
}

// New returns a manager. A nil Runtime or Registry getter is tolerated at construction
// and reported at Run, matching capreg.Build's tolerance of a partially wired Deps.
func New(d Deps) *Manager {
	return &Manager{
		deps: d,
		sem:  make(chan struct{}, maxConcurrentRuns),
		runs: NewRunLog(maxRuns),
	}
}

// Runs exposes the run log for the control plane.
func (m *Manager) Runs() *RunLog { return m.runs }

// Packages exposes the installed-automation store for the control plane. Nil when
// scripting is configured without a data directory.
func (m *Manager) Packages() *Store { return m.deps.Store }

// Storage exposes the automation key/value state, for project save and load.
func (m *Manager) Storage() *Storage { return m.deps.Storage }

// RunRequest is one script to execute.
type RunRequest struct {
	Source string
	Input  json.RawMessage

	// Caller is the launching token's principal. Its grants are deliberately not
	// consulted; its policy fields are, and only to narrow. See runPrincipal.
	Caller capability.Principal

	Trigger string
	Limits  jsruntime.Limits

	// AutomationID names the installed automation this run belongs to, which is what
	// gives it a storage namespace. Empty for a one-shot: there is nowhere durable for
	// such a run to write, and saying so is better than a scratchpad that vanishes.
	AutomationID      string
	AutomationVersion string

	// TriggerData is the event payload, merged into ctx.trigger. References only.
	TriggerData json.RawMessage

	// NoSend drops the send-capable capabilities from the run's grants. Set for a lens,
	// which renders bytes the operator is already looking at and has no business
	// reaching a target.
	NoSend bool
}

// ErrBusy means the concurrent-run limit is reached.
var ErrBusy = errors.New("Joro is already running the maximum number of scripts; retry shortly")

// Run executes a script and records the outcome.
//
// The returned error means the run could not be attempted — no runtime, no registry,
// or no free slot. Everything else, including a script that threw, timed out, blew its
// budget or was killed for memory, comes back as a *Run whose Result carries the
// reason. A caller therefore has one thing to report and one place to look.
func (m *Manager) Run(ctx context.Context, req RunRequest) (*Run, error) {
	if m.deps.Runtime == nil {
		return nil, errors.New("the script runtime is unavailable")
	}
	if m.deps.Registry == nil {
		return nil, errors.New("the capability registry is unavailable")
	}
	reg := m.deps.Registry()
	if reg == nil {
		return nil, errors.New("the capability registry is unavailable")
	}

	select {
	case m.sem <- struct{}{}:
		defer func() { <-m.sem }()
	default:
		return nil, ErrBusy
	}

	runID := newRunID()
	sendCaps := sendCapsFrom(reg)
	principal := runPrincipal(req.Caller, runID, sendCaps, req.NoSend)

	// Tear down everything keyed on the run's synthetic identity. Without the Forget
	// the registry's limiter map grows an entry per run and nothing ever prunes it;
	// without the Reset a run's captured session would outlive it in a jar no later
	// run can reach but which still counts against the jar ceiling.
	defer func() {
		reg.Forget(runID)
		if m.deps.Contexts != nil {
			m.deps.Contexts.Reset(runID)
		}
	}()

	started := time.Now()
	rtReq := jsruntime.Request{
		Source: req.Source,
		Input:  req.Input,
		Limits: req.Limits,
		Meta: jsruntime.Meta{
			RunID:             runID,
			StartedAt:         started.UTC().Format(time.RFC3339),
			TriggerType:       orDefault(req.Trigger, "manual"),
			TriggerData:       req.TriggerData,
			AutomationID:      req.AutomationID,
			AutomationVersion: req.AutomationVersion,
		},
		SendCaps: sendCapsFrom(reg),
	}

	res, err := m.deps.Runtime.Run(ctx, rtReq, m.bridgeFor(reg, principal, req.AutomationID))
	if err != nil {
		// The runtime itself failed. Record it anyway: an operator investigating a
		// script that "did nothing" needs to find the attempt.
		res = jsruntime.Result{
			Reason:     jsruntime.ReasonRuntimeFailure,
			Err:        err.Error(),
			DurationMs: time.Since(started).Milliseconds(),
		}
	}

	run := &Run{
		ID:           runID,
		StartedAt:    started.UTC(),
		DurationMs:   res.DurationMs,
		TokenID:      req.Caller.TokenID,
		TokenName:    req.Caller.TokenName,
		AutomationID: req.AutomationID,
		Trigger:      rtReq.Meta.TriggerType,
		Bundle:       BundleVersion,
		Source:       req.Source,
		SourceHash:   HashSource(req.Source),
		Result:       res,
	}
	m.runs.Add(run)
	return run, nil
}

// ErrNotRunnable means an installed automation exists but is not armed.
var ErrNotRunnable = errors.New("this automation is not enabled")

// List returns every installed automation, without source. Used by the script.list
// capability and by the control plane.
func (m *Manager) List() []Summary {
	if m.deps.Store == nil {
		return nil
	}
	all := m.deps.Store.List()
	out := make([]Summary, 0, len(all))
	for _, a := range all {
		out = append(out, a.Summarize())
	}
	return out
}

// InvokeRequest names one invocation of an installed automation. A struct rather than a
// parameter list: it grew to six, and a trigger payload silently going missing is exactly
// the mistake positional arguments invite.
type InvokeRequest struct {
	ID     string
	Input  json.RawMessage
	Caller capability.Principal

	Trigger     string
	TriggerData json.RawMessage

	// OperatorRun allows running an automation that is not armed. True only for the
	// operator's own request through the UI, because reviewing something means being
	// able to run it before enabling it. Never true for an agent.
	OperatorRun bool

	// NoSend drops the send-capable grants; see RunRequest.NoSend.
	NoSend bool
}

// Invoke runs an installed automation.
func (m *Manager) Invoke(ctx context.Context, req InvokeRequest) (*Run, error) {
	id, input, caller := req.ID, req.Input, req.Caller
	trigger, operatorRun := req.Trigger, req.OperatorRun
	if m.deps.Store == nil {
		return nil, errors.New("installed automations are unavailable")
	}
	a, err := m.deps.Store.Load(id)
	if err != nil {
		return nil, err
	}
	if !operatorRun && !a.Runnable() {
		if a.State.Paused {
			return nil, fmt.Errorf("%w: it was paused automatically (%s)", ErrNotRunnable, a.State.PausedReason)
		}
		return nil, ErrNotRunnable
	}

	// A trigger-fired run has no launching token, so nothing carries a host whitelist
	// into it and scope is its only bound. Where the operator has set one on the
	// automation, apply it. Only when the caller has none of its own: a token's leash is
	// already the stricter authority, and two whitelists in one field cannot be ANDed.
	if len(caller.HostAllow) == 0 && len(a.State.HostAllow) > 0 {
		caller.HostAllow = slices.Clone(a.State.HostAllow)
	}

	run, err := m.Run(ctx, RunRequest{
		Source:            a.Source,
		Input:             input,
		Caller:            caller,
		Trigger:           orDefault(trigger, TriggerManual),
		TriggerData:       req.TriggerData,
		Limits:            a.Limits(),
		AutomationID:      a.Manifest.ID,
		AutomationVersion: a.Manifest.Version,
		NoSend:            req.NoSend,
	})
	if err != nil {
		return nil, err
	}
	m.noteLastRun(a.Manifest.ID, run)
	return run, nil
}

// noteLastRun records the outcome on the automation's sidecar, so the list view can show
// what happened without holding the whole run log. Best-effort: a run that succeeded must
// not be reported as failed because a sidecar write did.
func (m *Manager) noteLastRun(id string, run *Run) {
	if m.deps.Store == nil || run == nil {
		return
	}
	if _, err := m.deps.Store.SetState(id, func(st *State) {
		st.LastRun = &LastRun{ID: run.ID, At: run.StartedAt, Reason: run.Result.Reason}
	}); err != nil {
		log.Printf("[automation] %s: recording last run: %v", id, err)
	}
}

// AutomationPrincipal is the caller for a run nothing launched — a trigger firing.
//
// It carries a name for the audit trail and no HostAllow, because there is no token to
// inherit one from. Such a run is therefore bounded by scope alone, which is the
// engagement boundary and the thing the operator was already relying on; runPrincipal
// still pins RequireScope on and credentials off.
func AutomationPrincipal(id string) capability.Principal {
	return capability.Principal{TokenName: "automation:" + id}
}

// sendCapsFrom lists the granted capability IDs that put bytes on the wire, so the
// runtime can charge them against the run's separate send budget. Read from the
// registry rather than hardcoded, so a capability that gains SendsTraffic in a later
// release is counted without this package being edited.
func sendCapsFrom(reg Invoker) []string {
	var out []string
	for _, id := range BundleGrants() {
		if c, ok := reg.Get(id); ok && c.SendsTraffic {
			out = append(out, id)
		}
	}
	return out
}

// bridgeFor builds the host bridge for one run.
//
// Two types rather than one with a nil check: a one-shot run gets a bridge that does not
// implement jsruntime.StorageBridge at all, so "this run has no namespace" is a fact the
// type system carries rather than a condition someone has to remember to test.
func (m *Manager) bridgeFor(reg Invoker, p capability.Principal, automationID string) jsruntime.HostBridge {
	base := registryBridge{inv: reg, principal: p}
	if automationID == "" || m.deps.Storage == nil {
		return &base
	}
	return &storageBridge{
		registryBridge: base,
		ns:             namespaced{s: m.deps.Storage, id: automationID},
	}
}

// registryBridge is the only thing a script can reach. Every call becomes a
// Registry.Invoke under the run's principal, which is what makes a script's authority
// identical to a token's: same guard, same scope check, same limits, same audit row.
type registryBridge struct {
	inv       Invoker
	principal capability.Principal
}

// storageBridge adds joro.storage for a run that belongs to an installed automation.
type storageBridge struct {
	registryBridge
	ns namespaced
}

func (b *storageBridge) Storage(ctx context.Context, op, key string, value json.RawMessage) (json.RawMessage, error) {
	return b.ns.Storage(ctx, op, key, value)
}

func (b *registryBridge) Invoke(ctx context.Context, id string, args json.RawMessage) (json.RawMessage, error) {
	res, err := b.inv.Invoke(ctx, b.principal, id, args)
	if err != nil {
		code := capability.CodeOf(err)
		return nil, &jsruntime.CallError{
			Code:   code,
			Msg:    messageOf(err),
			Denied: isDenial(code),
		}
	}
	// The registry hands back a Go value; marshalling here is what keeps the pipe and
	// the VM boundary JSON-only. A result that will not marshal is the handler's bug,
	// and the script should hear about it as a failed call rather than a silent empty.
	out, merr := json.Marshal(res.Data)
	if merr != nil {
		return nil, &jsruntime.CallError{
			Code: capability.CodeHandlerError,
			Msg:  fmt.Sprintf("the result of %s could not be encoded: %v", id, merr),
		}
	}
	return out, nil
}

// messageOf returns a capability error's own message, without the code prefix that
// Error() adds — the code travels as a separate field and the script sees both.
func messageOf(err error) string {
	var ce *capability.Error
	if errors.As(err, &ce) && ce.Msg != "" {
		return ce.Msg
	}
	return err.Error()
}

// isDenial reports whether a code means "you may not", as opposed to "it did not
// work". A run that ends on an uncaught denial is reported differently because the fix
// is a grant or a scope rule, not a change to the script.
//
// This mirrors the registry's own unexported classification. The exported code
// constants are the shared contract; a code added there and not here degrades to
// "handler error", which reads as a script problem rather than a policy one.
func isDenial(code string) bool {
	switch code {
	case capability.CodeForbidden,
		capability.CodeScopeDisabled,
		capability.CodeScopeEmpty,
		capability.CodeOutOfScope,
		capability.CodeHostNotAllowed,
		capability.CodeTokenRestricted,
		capability.CodeRateLimited,
		capability.CodeBusy:
		return true
	}
	return false
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
