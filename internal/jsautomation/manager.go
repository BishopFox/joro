// Package jsautomation runs installed automations: sandboxed JavaScript against Joro's
// capability registry, and local commands.
//
// It owns three things the execution tiers deliberately do not: the principal a run acts
// as, the budget the run is held to, and the record of what it did. jsruntime knows how to
// execute JavaScript and nothing about Joro; localcmd knows how to supervise a process and
// nothing about Joro; this package knows about Joro and nothing about either.
//
// The dependency shape is the interesting part. This package is handed an Invoker — the
// sealed capability registry behind a three-method interface — and never a service
// object. A script's reach is therefore exactly the registry's, evaluated call by call
// with the registry's own guard, limits and audit trail. There is no second
// authorization path to keep in step, and no host function that could grow one.
//
// # Two kinds, one lifecycle
//
// The package name says JavaScript and the package no longer only runs it, which is worth
// a sentence rather than leaving a reader to notice. Manifest.Kind selects the execution
// half; everything around it is shared, deliberately and completely — the same store, the
// same trigger dispatcher, the same lens declaration, the same operator overrides, the
// same bounded run log. A second package for commands would have meant a second copy of
// each of those, and the copies would have drifted.
//
// The two halves differ in exactly one way that matters, and command.go states it at
// length: a script's authority is a grant bundle the registry evaluates call by call,
// while a command's authority is the operator having armed it. There is no capability for
// running a local command and no way to grant one — see Store.InstallAs and Invoke.
package jsautomation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/jsruntime"
	"github.com/BishopFox/joro/internal/localcmd"
)

// How many scripts execute at once is the operator's to set — jsruntime.HostBudget
// carries it, with the default and the ceiling declared beside the rest of the budget.
//
// Each active run occupies up to two of the registry's global concurrency slots: one for
// the outer capability, held for the run's whole duration, and one for whichever SDK call
// is in flight. Leaving this unbounded would let a handful of scripts consume every slot
// and starve the operator's other automation calls, which is the failure the global
// semaphore exists to prevent in the first place.

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

	// Budget is the operator's run policy: the default and the maximum per field, plus
	// the host limits. A getter because it is edited at runtime and lives in the token
	// store, which this package does not import; nil, or a zero policy, means the
	// runtime's own defaults and ceilings apply.
	Budget func() jsruntime.BudgetPolicy

	// ScopeConfigured reports whether the operator has set a capture boundary: scope
	// enabled with at least one rule. It is the policy a run no token launched inherits —
	// bounded by their rules where they set some, bounded by nothing where they did not,
	// which is how their browser, Manipulate and the fuzzer already behave. The rule
	// count is part of the question: scope enabled with no rules restricts nothing, so
	// reading it as a restriction would refuse every send from an operator who set none.
	//
	// A getter for the same reason Budget is one — it changes at runtime, and this package
	// must not hold a proxy handle. Nil means fail closed, not fail open: an unwired
	// getter is a programming error, and refusing every send is the loud failure where
	// allowing them all is the silent one.
	ScopeConfigured func() bool

	// Commands reports whether local command automations may run at all, from
	// --automation-commands. Nil or false means a command package still loads and lists
	// — so the operator can see it and be told which flag it wants — but never runs.
	//
	// A getter rather than a bool so the shape matches every other policy field here,
	// and so a future runtime toggle needs no signature change.
	Commands func() bool

	// CommandBudget is the operator's policy for command runs, a separate one from
	// Budget: see the header of internal/localcmd/budget.go for why the two are not one
	// struct. Nil, or a zero policy, means localcmd's own defaults and ceilings.
	CommandBudget func() localcmd.Policy

	// Scratch is the directory holding per-run working directories for command runs.
	// Empty disables them, reported at the run rather than at construction.
	Scratch string

	// Captures resolves one captured transaction's raw bytes by sequence number, for a
	// command run's stdin and input files.
	//
	// A narrow getter rather than the capture store itself, and that is the point: this
	// package holding a *proxy.Store would put List, Clear and Sitemap within reach of
	// everything here, when what a command run needs is two byte slices for one
	// sequence number. Same reasoning as capreg.Deps.SetHighlight being a func.
	//
	// Nil means a command run gets no transaction bytes, which a spec that asked for
	// them reports as an empty stdin rather than as a failure.
	Captures func(seq int) (reqRaw, respRaw []byte, ok bool)

	// ProxyURL and CAFile are exported into a command's environment when its spec sets
	// useProxy, so its traffic can be captured and its TLS verified. Empty means the
	// variables are not set and the command connects directly.
	ProxyURL string
	CAFile   string
}

// Manager runs scripts and remembers what they did.
type Manager struct {
	deps Deps
	runs *RunLog

	// A counter rather than a buffered channel, because the ceiling is the operator's
	// and they can change it between runs. Resizing a channel is not a thing; comparing
	// against the value read at admission is.
	//
	// Two counters, not one. A script run holds up to two of the capability registry's
	// eight global slots, which is what its ceiling is set against; a command run holds
	// none of them and instead costs a process with its own memory and its own network
	// activity. Sharing one counter would mean raising the ceiling for either kind
	// raised it for both, against two limits that are not measuring the same thing.
	mu        sync.Mutex
	active    int
	activeCmd int
}

// New returns a manager. A nil Runtime or Registry getter is tolerated at construction
// and reported at Run, matching capreg.Build's tolerance of a partially wired Deps.
func New(d Deps) *Manager {
	return &Manager{deps: d, runs: NewRunLog(maxRuns)}
}

// admit takes a run slot if the operator's ceiling allows one.
func (m *Manager) admit(max int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active >= max {
		return false
	}
	m.active++
	return true
}

func (m *Manager) release() {
	m.mu.Lock()
	m.active--
	m.mu.Unlock()
}

// admitCmd takes a command run slot if the operator's ceiling allows one.
func (m *Manager) admitCmd(max int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeCmd >= max {
		return false
	}
	m.activeCmd++
	return true
}

func (m *Manager) releaseCmd() {
	m.mu.Lock()
	m.activeCmd--
	m.mu.Unlock()
}

// commandsEnabled reports whether --automation-commands was given. Nil getter reads as
// disabled: a wiring mistake must not be what enables local execution.
func (m *Manager) commandsEnabled() bool {
	return m.deps.Commands != nil && m.deps.Commands()
}

// CommandsEnabled reports the same to the control plane, so a handler can explain a
// refusal before attempting a run.
func (m *Manager) CommandsEnabled() bool { return m.commandsEnabled() }

// CommandBudget reports the operator's command-run policy, or a zero one when none is
// configured.
func (m *Manager) CommandBudget() localcmd.Policy { return m.commandPolicy() }

func (m *Manager) commandPolicy() localcmd.Policy {
	if m.deps.CommandBudget == nil {
		return localcmd.Policy{}
	}
	return m.deps.CommandBudget()
}

// Runs exposes the run log for the control plane.
func (m *Manager) Runs() *RunLog { return m.runs }

// Budget reports the operator's run policy, or a zero one when none is configured.
// Exposed so the control plane and the script capability can read what a run would be
// held to without reaching for the token store themselves.
func (m *Manager) Budget() jsruntime.BudgetPolicy { return m.budget() }

func (m *Manager) budget() jsruntime.BudgetPolicy {
	if m.deps.Budget == nil {
		return jsruntime.BudgetPolicy{}
	}
	return m.deps.Budget()
}

// scopeConfigured reports whether the operator has set a capture boundary. Nil getter
// reads as "configured", so a wiring mistake refuses sends rather than permitting them.
func (m *Manager) scopeConfigured() bool {
	if m.deps.ScopeConfigured == nil {
		return true
	}
	return m.deps.ScopeConfigured()
}

// Packages exposes the installed-automation store for the control plane. Nil when
// scripting is configured without a data directory.
func (m *Manager) Packages() *Store { return m.deps.Store }

// Storage exposes the automation key/value state, for project save and load.
func (m *Manager) Storage() *Storage { return m.deps.Storage }

// InstallPackage stores a new automation, disabled and unarmed, recording the caller as
// its author.
//
// A forwarder rather than logic: the store owns validation, the disabled default, the
// package ceiling and the path rules. It exists so a capability can reach installation
// through capreg.ScriptRunner instead of through a capreg.Deps field — see that interface.
func (m *Manager) InstallPackage(mf Manifest, source, author string) (*Automation, error) {
	if m.deps.Store == nil {
		return nil, errors.New("installed automations are unavailable")
	}
	return m.deps.Store.InstallAs(mf, source, author)
}

// ReplacePackage overwrites an installed automation the operator has not enabled.
func (m *Manager) ReplacePackage(id string, mf Manifest, source, expectedHash, author string) (*Automation, error) {
	if m.deps.Store == nil {
		return nil, errors.New("installed automations are unavailable")
	}
	return m.deps.Store.ReplaceDisabled(id, mf, source, expectedHash, author)
}

// RunRequest is one script to execute.
type RunRequest struct {
	Source string
	Input  json.RawMessage

	// Caller is whoever started the run. Its grants are deliberately not consulted. Its
	// policy fields are, when it is a token: a token-launched run inherits that token's
	// policy verbatim, and a run nothing launched inherits the operator's own
	// configuration instead. See runPrincipal.
	Caller capability.Principal

	Trigger string
	Limits  jsruntime.Limits

	// Command, when set, makes this a command run: Source is then the spec's rendering
	// rather than a program, and nothing in jsruntime is involved.
	//
	// A field rather than a kind enum, so the branch in Run is a nil check on the thing
	// it needs rather than a string comparison followed by a lookup that could disagree
	// with it.
	Command       *localcmd.Spec
	CommandLimits localcmd.Limits

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

// ErrCommandBusy is ErrBusy for a command run. A separate sentinel because the two
// ceilings are separate and an operator told "the maximum number of scripts" while looking
// at a command would go and edit the wrong field.
var ErrCommandBusy = errors.New("Joro is already running the maximum number of commands; retry shortly")

// Run executes an automation and records the outcome.
//
// The returned error means the run could not be attempted — no runtime, no registry, or no
// free slot. Everything else, including a script that threw, a command that exited
// non-zero, and either kind timing out or being killed, comes back as a *Run whose Result
// carries the reason. A caller therefore has one thing to report and one place to look.
//
// Both kinds end here, which is the property worth keeping: the run log, the outcome code,
// the last-run pointer and the operator's view of what happened all have exactly one
// producer.
func (m *Manager) Run(ctx context.Context, req RunRequest) (*Run, error) {
	runID := newRunID()
	started := time.Now()

	res, principal, bundle, err := m.execute(ctx, runID, req)
	if err != nil {
		return nil, err
	}
	// The one place a run's fate is stamped with its machine-readable code. Both tiers
	// synthesize reasons deep inside themselves — a worker protocol failure, a process
	// that vanished — and neither has to know a code exists.
	res.Outcome = outcomeFor(req, res.Reason)

	run := &Run{
		ID:           runID,
		StartedAt:    started.UTC(),
		DurationMs:   res.DurationMs,
		TokenID:      req.Caller.TokenID,
		TokenName:    req.Caller.TokenName,
		AutomationID: req.AutomationID,
		Trigger:      orDefault(req.Trigger, TriggerManual),
		Bundle:       bundle,
		Source:       req.Source,
		SourceHash:   HashSource(req.Source),
		Result:       res,

		// The policy the run was actually held to, not the policy anyone asked for. It
		// varies with the launching token, or with the operator's scope configuration, so
		// a run that reported only its budget would leave the operator inferring the half
		// most likely to have refused its sends.
		//
		// Both false for a command, and that is accurate rather than a default: a command
		// makes no guarded call, so no scope decision and no credential decision was
		// taken about it. The UI reads Bundle to tell the two cases apart.
		RequireScope: principal.RequireScope,
		Credentials:  principal.AllowCredentials,
	}
	m.runs.Add(run)
	return run, nil
}

// outcomeFor stamps the code for a reason, from the vocabulary of whichever tier produced
// it. The two vocabularies overlap in wording ("timeout", "cancelled") and each maps its
// own, so neither has to know about the other's additions.
func outcomeFor(req RunRequest, reason string) string {
	if req.Command != nil {
		return localcmd.OutcomeFor(reason)
	}
	return jsruntime.OutcomeFor(reason)
}

// execute runs the body and reports what it was held to.
//
// Split from Run so the record above is built once for both kinds. It returns the
// principal because a script's is synthesized here and is what the record's policy fields
// report; a command has none, and the zero value says so.
func (m *Manager) execute(ctx context.Context, runID string,
	req RunRequest) (jsruntime.Result, capability.Principal, string, error) {
	if req.Command != nil {
		if !m.admitCmd(m.commandPolicy().Host.Resolved().ConcurrentRuns) {
			return jsruntime.Result{}, capability.Principal{}, "", ErrCommandBusy
		}
		defer m.releaseCmd()

		// No principal, no registry, no bundle. There is nothing to authorize call by
		// call, which is exactly why running one at all takes a launch flag and an
		// operator arming it.
		res, err := m.runCommand(ctx, runID, req)
		return res, capability.Principal{}, "", err
	}
	return m.executeScript(ctx, runID, req)
}

// executeScript is the JavaScript half: the body of Run as it was before commands existed.
func (m *Manager) executeScript(ctx context.Context, runID string,
	req RunRequest) (jsruntime.Result, capability.Principal, string, error) {
	var none capability.Principal

	if m.deps.Runtime == nil {
		return jsruntime.Result{}, none, "", errors.New("the script runtime is unavailable")
	}
	if m.deps.Registry == nil {
		return jsruntime.Result{}, none, "", errors.New("the capability registry is unavailable")
	}
	reg := m.deps.Registry()
	if reg == nil {
		return jsruntime.Result{}, none, "", errors.New("the capability registry is unavailable")
	}

	policy := m.budget()
	if !m.admit(policy.Host.Resolved().ConcurrentRuns) {
		return jsruntime.Result{}, none, "", ErrBusy
	}
	defer m.release()

	sendCaps := sendCapsFrom(reg)
	principal := runPrincipal(req.Caller, runID, sendCaps, req.NoSend, m.scopeConfigured())

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
		// The one place the operator's global budget is applied, so it holds every
		// path equally: an agent's script.run, the operator's own inline run from the
		// editor, script.invoke, a lens, and a trigger firing.
		Limits: req.Limits.NormalizeWith(policy),
		Meta: jsruntime.Meta{
			RunID:             runID,
			StartedAt:         started.UTC().Format(time.RFC3339),
			TriggerType:       orDefault(req.Trigger, "manual"),
			TriggerData:       req.TriggerData,
			AutomationID:      req.AutomationID,
			AutomationVersion: req.AutomationVersion,
		},
		SendCaps: sendCaps,
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
	return res, principal, BundleVersion, nil
}

// ErrNotRunnable means an installed automation exists but is not armed.
var ErrNotRunnable = errors.New("this automation is not enabled")

// ErrCommandNotInvokable means a token tried to start a command automation. See Invoke.
var ErrCommandNotInvokable = errors.New("this automation runs a local command, which only " +
	"the operator can start")

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

	// A token may not start a command automation, and this is the gate that holds it.
	//
	// script.invoke exists, is registered whenever --automation-scripting is on, and is
	// grantable by hand — so without this a token holding it could run any command
	// package the operator had armed. That is a different thing from what the operator
	// agreed to when they armed it: arming says "run this on the trigger I chose", not
	// "let anything holding a grant run it on demand".
	//
	// Derived from the caller's TokenID rather than carried as a flag, reusing
	// tokenLaunched, because every token path receives its principal from
	// Registry.Invoke, which always sets it. A token path added later gets this for
	// free, where a bool would have to be remembered.
	if a.Manifest.IsCommand() && tokenLaunched(caller) {
		return nil, ErrCommandNotInvokable
	}

	// A trigger-fired run has no launching token, so nothing carries a host whitelist
	// into it and scope is its only bound. Where the operator has set one on the
	// automation, apply it. Only when the caller has none of its own: a token's leash is
	// already the stricter authority, and two whitelists in one field cannot be ANDed.
	if len(caller.HostAllow) == 0 && len(a.State.HostAllow) > 0 {
		caller.HostAllow = slices.Clone(a.State.HostAllow)
	}

	rr := RunRequest{
		Source:            a.Source,
		Input:             input,
		Caller:            caller,
		Trigger:           orDefault(trigger, TriggerManual),
		TriggerData:       req.TriggerData,
		Limits:            a.RequestedBudget().Limits(),
		AutomationID:      a.Manifest.ID,
		AutomationVersion: a.Manifest.Version,
		NoSend:            req.NoSend,
	}
	if a.Manifest.IsCommand() {
		rr.Command = a.Manifest.Command
		// The command budget's only per-automation input is the wall clock, which the
		// manifest and the operator's override already narrow through RequestedBudget.
		// Resolved against the operator's command policy here, so the same "narrowed by
		// whoever asked for less, then held to the operator's global" rule applies to
		// both kinds.
		rr.CommandLimits = localcmd.Limits{
			Timeout: a.RequestedBudget().Limits().Timeout,
		}.NormalizeWith(m.commandPolicy())
	}

	run, err := m.Run(ctx, rr)
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
		st.LastRun = &LastRun{
			ID:      run.ID,
			At:      run.StartedAt,
			Reason:  run.Result.Reason,
			Outcome: run.Result.Outcome,
		}
	}); err != nil {
		log.Printf("[automation] %s: recording last run: %v", id, err)
	}
}

// AutomationPrincipal is the caller for a run nothing launched — a trigger firing, or the
// operator's own request through the UI.
//
// It carries a name for the audit trail and deliberately no policy. Policy for such a run
// is not this function's to state: there is no token to inherit from, so runPrincipal
// resolves it from the operator's own configuration instead. Do not "fix" the permissive
// look of the zero value by pinning something on here — a value written here would
// silently outrank the operator's configuration, which is the one thing it must not do.
//
// HostAllow is likewise absent, and Manager.Invoke substitutes the automation's own
// whitelist when the caller carries none.
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
