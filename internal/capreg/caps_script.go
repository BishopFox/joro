package capreg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/jsautomation"
	"github.com/BishopFox/joro/internal/jsruntime"
)

// ScriptRunner executes a sandboxed script. *jsautomation.Manager satisfies it.
//
// This file is the one place capreg imports internal/jsautomation, and the import is
// safe for the reason the package doc gives: jsautomation is not internal/api (which
// would be a cycle the compiler rejects) and not internal/automation (the token store).
// It holds a capability Invoker and a cookie-jar handle, so importing it hands a
// capability body no reach it did not already have.
type ScriptRunner interface {
	Run(ctx context.Context, req jsautomation.RunRequest) (*jsautomation.Run, error)
	// List reports the installed automations, without their source.
	List() []jsautomation.Summary
	// Invoke runs an installed automation. OperatorRun is never set from here: an
	// agent may run only what the operator has armed.
	Invoke(ctx context.Context, req jsautomation.InvokeRequest) (*jsautomation.Run, error)
	// Budget is the operator's run policy. Read here for the two host figures that
	// shape what an agent gets back — widening this interface rather than Deps, which
	// is the field set whose growth would break the import rule in build.go.
	Budget() jsruntime.BudgetPolicy

	// InstallPackage stores an automation the caller wrote, disabled and unarmed. The
	// operator arms it or nothing does, which is the same rule Invoke states above.
	// Widened here rather than on Deps for the reason Budget gives.
	InstallPackage(m jsautomation.Manifest, source, author string) (*jsautomation.Automation, error)

	// ReplacePackage overwrites an installed automation, and refuses one the operator has
	// enabled. Separate from InstallPackage because it backs a separate grant: a token
	// may be allowed to store automations without being allowed to overwrite them.
	ReplacePackage(id string, m jsautomation.Manifest, source, expectedHash, author string) (*jsautomation.Automation, error)
}

type scriptRunArgs struct {
	Source string          `json:"source"`
	Input  json.RawMessage `json:"input"`

	TimeoutMs    int `json:"timeoutMs"`
	MaxCalls     int `json:"maxCalls"`
	MaxSendCalls int `json:"maxSendCalls"`
}

type scriptInvokeArgs struct {
	ID    string          `json:"id"`
	Input json.RawMessage `json:"input"`
}

// scriptInstallArgs is the submittable half of a manifest.
//
// Deliberately absent, each for its own reason. entrypoint and sdkVersion: Normalize
// supplies both, there is one bundled file, and its name is Joro's to pick. limits: an
// author's request can only ever narrow what the operator already allows, so offering it
// buys nothing and costs a field for a caller to invent and an operator to check. lens: a
// lens runs unattended on every transaction the operator opens once it is enabled, which
// is the sharpest surface here, and the editor is where one belongs.
//
// minIntervalMs stays, because it combines by taking the larger of author and operator —
// declaring one is self-restraint, and it is the only field here a caller can use to make
// its own automation safer.
type scriptInstallArgs struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Description   string   `json:"description"`
	Source        string   `json:"source"`
	Triggers      []string `json:"triggers"`
	MinIntervalMs int      `json:"minIntervalMs"`
}

func (a scriptInstallArgs) manifest() jsautomation.Manifest {
	return jsautomation.Manifest{
		ID:            a.ID,
		Name:          a.Name,
		Version:       a.Version,
		Description:   a.Description,
		Triggers:      a.Triggers,
		MinIntervalMs: a.MinIntervalMs,
	}
}

type scriptReplaceArgs struct {
	scriptInstallArgs
	ExpectedHash string `json:"expectedHash"`
}

// Output shaping for the tool result.
//
// The logs and the returned value both have to fit inside this capability's output cap,
// and the cap is enforced after marshalling by erroring rather than truncating — so a
// script that logged generously would fail wholesale and the operator would lose the
// result along with the logs. The two figures are therefore set below the runtime's own
// defaults and leave room for the header, and the renderer truncates again as a backstop.
//
// They are the operator's to raise (jsruntime.HostBudget.AgentLogBytes and
// AgentResultBytes, read per call from the runner) but ScriptRunOutputCap is not: it is
// registered as this capability's MaxOutputBytes before the registry is sealed. Which is
// why the handler that stores the policy checks that the pair still fits inside it.
const (
	// ScriptRunHeaderRoom is what the run header, the truncation notes and the JSON
	// envelope need beside the logs and the result.
	ScriptRunHeaderRoom = 16 << 10

	// ScriptRunOutputCap is derived from the budget rather than chosen here, so the
	// operator-facing ceiling on the two agent figures and this registered cap cannot
	// drift apart. It is registered as MaxOutputBytes before the registry is sealed,
	// which is why it is the one number in this area the operator cannot raise.
	ScriptRunOutputCap = jsruntime.AgentOutputCap + ScriptRunHeaderRoom

	// scriptRunTimeout must exceed the longest run the operator can permit, so the tool
	// reports a real termination reason instead of the registry's bare timeout. Derived
	// for the same reason as the cap above: jsruntime.CapTimeout is what the budget
	// offers, and this has to stay above it.
	scriptRunTimeout = jsruntime.CapTimeout + 10*time.Second
)

// validateBundle panics if the SDK grant bundle names a capability a run must not hold.
//
// This is the only thing keeping the bundle's exclusions real. A run whose policy resolves
// unrestricted passes Capability.availableTo, so nothing in the guard would stop it
// invoking an UnrestrictedOnly capability the bundle happened to name — and
// validateProfiles is no help, since it only ever validates the five profiles and never
// sees jsruntime.CapabilityIDs().
//
// Called unconditionally from Build, not under d.Scripting. The bundle is a constant of
// the binary, so gating the check on --automation-scripting would ship the bug and bite
// only the operators who use the flag.
func validateBundle(r *capability.Registry) {
	for _, id := range jsautomation.BundleGrants() {
		c, ok := r.Get(id)
		switch {
		case !ok:
			panic(fmt.Sprintf("capreg: the SDK bundle grants %q, which is not registered. A renamed or "+
				"removed capability must be updated in jsruntime.Bindings too, or the SDK exposes a "+
				"method that throws on every call.", id))
		case capability.IsReserved(id):
			panic(fmt.Sprintf("capreg: the SDK bundle grants reserved ID %q", id))
		case c.UnrestrictedOnly:
			panic(fmt.Sprintf("capreg: the SDK bundle grants %q, which is UnrestrictedOnly. Scope is the "+
				"control that bounds a run, so a run must not be able to edit it — and a run launched "+
				"by an unrestricted token would now be permitted to.", id))
		case c.Privileged:
			panic(fmt.Sprintf("capreg: the SDK bundle grants privileged capability %q. Execution, C2 and "+
				"scripting are granted one at a time by hand; script.* in particular would let a script "+
				"launder its own budget by starting another.", id))
		}
	}
}

// agentCaps reports how much of a run the caller gets back, from the operator's policy.
func agentCaps(r ScriptRunner) (logBytes, resultBytes int) {
	h := r.Budget().Host.Resolved()
	return h.AgentLogBytes, h.AgentResultBytes
}

func registerScript(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "script.run",
		Class: capability.ClassScript,
		Title: "Run a JavaScript automation",

		// Privileged, and the flag is doing four jobs at once: it keeps this out of
		// the operator profile's automatic expansion, makes validateProfiles refuse
		// to bundle it into any profile, marks it in the grant picker behind a second
		// confirmation, and records it on every audit entry. All four are wanted,
		// because this is the one capability whose authority is not its own.
		Privileged: true,
		// A run can change Joro's state through its bundle — create findings and
		// notes, clear its session. It does not itself send traffic: each send inside
		// the script is a separate invocation with its own target extraction and its
		// own scope evaluation, which is stricter than one check here could be.
		Mutating: true,

		Description: "Run a JavaScript program in a sandbox, with Joro's automation SDK available as the " +
			"global `joro`. Define `async function run(ctx)`; whatever it returns is the result. This is how " +
			"you do work that would otherwise be dozens of separate tool calls — sweeping IDs, comparing " +
			"responses, walking a list of endpoints — in one call, at a fraction of the context. " +
			"The SDK covers reading history and captured requests, resending and batching, fuzzing, and " +
			"writing findings and notes: joro.http.read, joro.http.resend, joro.http.batch, joro.http.diff, " +
			"joro.history.list, joro.findings.create, joro.notes.create, and more; every method takes the same " +
			"arguments as the tool of the same name and throws on failure, with err.code carrying the reason. " +
			"There is no network, filesystem, process or module access — joro is the only way out. Every send " +
			"the code makes is bounded by this token's own scope requirement and host whitelist, exactly as a " +
			"direct http_resend would be, and credential headers are masked unless this token is allowed them; " +
			"the run report names both. Each run has its own request budget and " +
			"wall-clock deadline, both set by the operator and possibly above or below the maxima here; ask " +
			"for what you need, and read your result for what you were actually given. console.log output " +
			"and the return value both come back to you. A run here is ephemeral — nothing survives it but " +
			"the report. If the program turns out to be worth keeping, store it with script_install and the " +
			"operator can review and enable it.",

		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "source": {
      "type":"string",
      "description":"The program. Must define 'async function run(ctx)' at the top level. ctx carries {run:{id,startedAt}, trigger:{type}, input}. Bundle any dependencies in; nothing is resolvable at runtime."
    },
    "input": {
      "type":"object",
      "description":"Arbitrary JSON handed to the script as ctx.input. Use it to parameterize a script instead of rewriting its source."
    },
    "timeoutMs": {
      "type":"integer","minimum":1000,"maximum":600000,
      "description":"Wall-clock limit for the run. The maximum here is jsruntime.CapTimeout, the longest run this Joro can permit; the operator sets the default and may hold you below it, and a higher request is clamped, not refused."
    },
    "maxCalls": {
      "type":"integer","minimum":1,"maximum":500,
      "description":"Maximum SDK calls the run may make. The operator sets both the default and the most you may ask for; a higher request is clamped, not refused."
    },
    "maxSendCalls": {
      "type":"integer","minimum":1,"maximum":100,
      "description":"Maximum SDK calls that put bytes on the wire, set by the operator like maxCalls. Counted in addition to maxCalls, so a sending call spends one of each."
    }
  },
  "required":["source"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"source":"async function run(ctx) {\n  const base = await joro.http.fingerprint({ seq: ctx.input.seq });\n  return { base: base };\n}","input":{"seq":1842}}`),

		MaxOutputBytes: ScriptRunOutputCap,
		Timeout:        scriptRunTimeout,

		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args scriptRunArgs) (any, error) {
			if d.Script == nil {
				return nil, fmt.Errorf("the script runtime is unavailable")
			}
			if strings.TrimSpace(args.Source) == "" {
				return nil, &capability.Error{
					Code: capability.CodeInvalidArgs,
					Msg:  "source is required: define `async function run(ctx) { ... }`",
				}
			}

			logCap, resultCap := agentCaps(d.Script)
			run, err := d.Script.Run(ctx, jsautomation.RunRequest{
				Source:  args.Source,
				Input:   args.Input,
				Caller:  p,
				Trigger: "mcp",
				Limits: jsruntime.Limits{
					Timeout:        time.Duration(args.TimeoutMs) * time.Millisecond,
					MaxCalls:       args.MaxCalls,
					MaxSendCalls:   args.MaxSendCalls,
					MaxLogBytes:    logCap,
					MaxResultBytes: resultCap,
				},
			})
			if err != nil {
				if errors.Is(err, jsautomation.ErrBusy) {
					return nil, &capability.Error{Code: capability.CodeBusy, Msg: err.Error()}
				}
				return nil, err
			}

			// The run summary is the audit entry's change text. Without it the row
			// reads as a bare capability name, which for the one capability that can
			// do many things is the least useful thing it could say.
			capability.RecordChange(ctx, "%s", run.Summary())

			return renderRun(run, logCap, resultCap), nil
		}),
	})

	// The triggers enum below duplicates jsautomation.Triggers, as every schema in this
	// package duplicates the Go values it describes. Adding a trigger constant means
	// adding it here too; Manifest.Validate refuses an unknown one and names the known
	// set, so the drift fails loudly rather than silently accepting a dead subscription.
	const triggerEnum = `["manual","request.selected","detect.finding","fuzzer.complete","request.captured"]`

	r.MustRegister(capability.Capability{
		ID:    "script.install",
		Class: capability.ClassScript,
		Title: "Store a JavaScript automation for the operator",

		// Privileged for the same reasons script.run is, and Mutating because this is the
		// one capability that writes executable code into the operator's data directory.
		//
		// It adds no execution authority: what it writes cannot run until the operator
		// enables it. What it adds is durability and visibility, which is a different
		// thing from running something once and worth its own grant. What bounds it: the
		// id pattern admits no path separator and the store re-validates it at the join,
		// the entrypoint is Joro's to name, size is bounded by the operator's program-size
		// budget and count by jsautomation.MaxAgentPackages, and a package never travels
		// inside a project config.
		Privileged: true,
		Mutating:   true,

		Description: "Store a script as an installed automation, so it outlives this session and the " +
			"operator can read it, edit it, enable it or remove it in Settings → Automation. Run it with " +
			"script_run first: an automation nobody has seen work is not worth storing. It arrives " +
			"DISABLED and unarmed — the triggers you declare are a request, not an arming, script_invoke " +
			"will refuse it, and only the operator can change that. An id that already exists is a " +
			"refusal, not an overwrite; replacing stored code is script_replace, a separate grant. You " +
			"cannot read any installed automation's source back, including your own.",

		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id": {
      "type":"string",
      "description":"Permanent handle: lowercase letters, digits, hyphen and underscore, starting with a letter or digit, 64 characters at most. It is the directory name, the script_invoke handle and the joro.storage namespace, and it cannot be changed later."
    },
    "name": {"type":"string","description":"Human label for the operator's list, 80 characters at most. Defaults to the id."},
    "version": {"type":"string","description":"Your own version string, 32 characters at most. Defaults to 0.0.0."},
    "description": {
      "type":"string",
      "description":"What this automation does and when it should run, 400 characters at most. The operator reads this before deciding whether to enable it, which makes it the most useful field here."
    },
    "source": {
      "type":"string",
      "description":"The program, identical in shape to script_run's: must define 'async function run(ctx)' at the top level. Compiled before it is stored, so a syntax error is refused rather than saved. Bundle any dependencies in; nothing is resolvable at runtime."
    },
    "triggers": {
      "type":"array",
      "items":{"type":"string","enum":` + triggerEnum + `},
      "description":"Events this automation is written to handle. A declaration only: nothing is armed until the operator enables the automation, and they can switch off any one of these. Defaults to manual."
    },
    "minIntervalMs": {
      "type":"integer","minimum":0,
      "description":"Shortest gap between two triggered runs. The operator's own figure is combined with this by taking the longer, so asking for space here is the one limit you can genuinely tighten."
    }
  },
  "required":["id","source"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"id":"idor-sweep","name":"IDOR sweep","version":"0.1.0","description":"Resends a request with neighbouring object ids and reports which ones answer 200.","source":"async function run(ctx) {\n  return { checked: ctx.input.seq };\n}","triggers":["manual"]}`),

		MaxOutputBytes: 4 << 10,

		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args scriptInstallArgs) (any, error) {
			if err := checkScriptWrite(d, args); err != nil {
				return nil, err
			}
			a, err := d.Script.InstallPackage(args.manifest(), args.Source, storedBy(p))
			if err != nil {
				return nil, storeError(err, "script_replace")
			}

			capability.RecordChange(ctx, "store %s v%s (%d bytes, disabled, triggers %s): sha256:%s",
				a.Manifest.ID, a.Manifest.Version, len(a.Source),
				joinOr(a.Manifest.Triggers, "-"), short(a.SourceHash))
			announceStored(d, a, p, true)
			return renderStored(a, false), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "script.replace",
		Class: capability.ClassScript,
		Title: "Replace a stored automation's code",

		// A separate grant from script.install on purpose: storing something new and
		// rewriting something that is already there are different acts, and an operator
		// should be able to permit the first without the second.
		//
		// The one test is whether the operator has the automation enabled. A disabled
		// automation may be replaced whoever wrote it, including one the operator wrote
		// and left switched off — so this grant is wider than "iterate on your own drafts"
		// and the description says so.
		Privileged: true,
		Mutating:   true,

		Description: "Replace the code of an automation already stored on this Joro, by id. Only one the " +
			"operator does not currently have enabled: arming an automation is them agreeing to supervise " +
			"that code, so replacing it underneath them is refused and they have to disable it first. " +
			"Otherwise any stored automation can be replaced, including one they wrote themselves. State " +
			"the sourceHash you are replacing, from script_list; a stale one is refused rather than " +
			"overwriting whatever is there now. The replacement is stored disabled if it was disabled, " +
			"which it must have been, so nothing is armed by this call.",

		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id": {"type":"string","description":"The automation id, from script_list."},
    "expectedHash": {
      "type":"string",
      "description":"The sourceHash script_list reports for this automation right now. Required: it is what stops this call overwriting a revision you have not seen."
    },
    "name": {"type":"string","description":"Human label for the operator's list, 80 characters at most. Defaults to the id."},
    "version": {"type":"string","description":"Your own version string, 32 characters at most. Bump it when the source changes."},
    "description": {"type":"string","description":"What this automation does and when it should run, 400 characters at most."},
    "source": {
      "type":"string",
      "description":"The replacement program. Must define 'async function run(ctx)' at the top level, and is compiled before it is stored."
    },
    "triggers": {
      "type":"array",
      "items":{"type":"string","enum":` + triggerEnum + `},
      "description":"Events this automation is written to handle. A trigger the operator switched off stays off, and a newly declared one is not armed by being declared."
    },
    "minIntervalMs": {"type":"integer","minimum":0,"description":"Shortest gap between two triggered runs; combined with the operator's by taking the longer."}
  },
  "required":["id","source","expectedHash"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"id":"idor-sweep","version":"0.2.0","expectedHash":"9f2b1c0d5e6a7b8c","source":"async function run(ctx) {\n  return { checked: ctx.input.seq };\n}"}`),

		MaxOutputBytes: 4 << 10,

		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args scriptReplaceArgs) (any, error) {
			if err := checkScriptWrite(d, args.scriptInstallArgs); err != nil {
				return nil, err
			}
			a, err := d.Script.ReplacePackage(args.ID, args.manifest(), args.Source,
				args.ExpectedHash, storedBy(p))
			if err != nil {
				return nil, storeError(err, "script_install")
			}

			capability.RecordChange(ctx, "replace %s v%s (was sha256:%s): sha256:%s",
				a.Manifest.ID, a.Manifest.Version, short(args.ExpectedHash), short(a.SourceHash))
			announceStored(d, a, p, false)
			return renderStored(a, true), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:         "script.list",
		Class:      capability.ClassScript,
		Title:      "List installed automations",
		Privileged: true,
		Description: "The automations installed on this Joro, with their id, version, whether the " +
			"operator has enabled them, which events they are armed for, and how their last run ended. " +
			"Use an id with script_invoke. Source is never returned: read what an automation does by " +
			"asking the operator, not by reading their code through this tool.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 32 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Script == nil {
				return nil, fmt.Errorf("the script runtime is unavailable")
			}
			return renderAutomations(invokable(d.Script.List())), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "script.invoke",
		Class: capability.ClassScript,
		Title: "Run an installed automation",

		// Privileged for the same reason script.run is: the code it runs holds the whole
		// SDK bundle. But it is a strictly narrower grant, and the more likely posture —
		// an operator can let an agent run automations they wrote and reviewed without
		// letting it submit code of its own.
		Privileged: true,
		Mutating:   true,

		Description: "Run an automation the operator has installed and enabled, by id, passing input " +
			"it is expecting. The code is theirs, not yours; you choose when to run it and what to feed " +
			"it. Returns the same run report as script_run: logs, the value it returned, and how it " +
			"ended. An automation that is not enabled cannot be invoked — ask the operator to enable it.",

		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id": {"type":"string","description":"The automation id, from script_list."},
    "input": {"type":"object","description":"JSON handed to the automation as ctx.input. What it expects is up to that automation."}
  },
  "required":["id"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"id":"idor-check","input":{"seq":1842}}`),

		MaxOutputBytes: ScriptRunOutputCap,
		Timeout:        scriptRunTimeout,

		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args scriptInvokeArgs) (any, error) {
			if d.Script == nil {
				return nil, fmt.Errorf("the script runtime is unavailable")
			}
			if strings.TrimSpace(args.ID) == "" {
				return nil, &capability.Error{Code: capability.CodeInvalidArgs, Msg: "id is required"}
			}

			logCap, resultCap := agentCaps(d.Script)
			run, err := d.Script.Invoke(ctx, jsautomation.InvokeRequest{
				ID:      args.ID,
				Input:   args.Input,
				Caller:  p,
				Trigger: jsautomation.TriggerManual,
			})
			switch {
			case errors.Is(err, jsautomation.ErrBusy):
				return nil, &capability.Error{Code: capability.CodeBusy, Msg: err.Error()}
			case errors.Is(err, jsautomation.ErrNotFound),
				// A command package is not listed by script_list, so an id naming one
				// arrived from somewhere else and the caller has no use for the
				// distinction. Reported as not installed for the same reason
				// Registry.Invoke swallows the difference between unknown and ungranted:
				// this tool must not become an oracle for what the operator has locally.
				errors.Is(err, jsautomation.ErrCommandNotInvokable):
				return nil, &capability.Error{
					Code: capability.CodeInvalidArgs,
					Msg:  fmt.Sprintf("no automation with id %q is installed; use script_list", args.ID),
				}
			case errors.Is(err, jsautomation.ErrNotRunnable):
				// Forbidden rather than invalid_args: the automation exists and the
				// argument was right, the operator has simply not armed it.
				return nil, &capability.Error{Code: capability.CodeForbidden, Msg: err.Error()}
			case err != nil:
				return nil, err
			}

			capability.RecordChange(ctx, "invoke %s: %s", args.ID, run.Summary())
			return renderRun(run, logCap, resultCap), nil
		}),
	})
}

// checkScriptWrite rejects what both write paths reject before the store is touched, so a
// caller hears about a missing argument rather than about a failed filesystem write.
func checkScriptWrite(d Deps, args scriptInstallArgs) error {
	switch {
	case d.Script == nil:
		return fmt.Errorf("the script runtime is unavailable")
	case strings.TrimSpace(args.ID) == "":
		return &capability.Error{Code: capability.CodeInvalidArgs, Msg: "id is required"}
	case strings.TrimSpace(args.Source) == "":
		return &capability.Error{
			Code: capability.CodeInvalidArgs,
			Msg:  "source is required: define `async function run(ctx) { ... }`",
		}
	}
	return nil
}

// storedBy names the author to record. The token's name rather than its id, because the
// value is shown to the operator beside the code — and a run nothing launched has no
// token, which reads as the operator's own.
func storedBy(p capability.Principal) string {
	if name := strings.TrimSpace(p.TokenName); name != "" {
		return name
	}
	return "automation"
}

// storeError maps the package store's sentinels onto capability codes. other names the
// sibling tool the caller should have reached for, which differs by direction: an id that
// exists wants script_replace, and one that does not wants script_install.
//
// ErrEnabled is forbidden rather than invalid_args for the reason ErrNotRunnable is in
// script.invoke: the argument was right and the automation exists, the operator's decision
// is what refuses. ErrTooManyPackages is forbidden rather than busy because busy means
// retry shortly, and nothing here clears without the operator removing something.
//
// A filesystem failure is returned unwrapped and surfaces as the registry's handler_error,
// which is the honest code for it: nothing the caller can restate would help.
// invokable drops the automations a token could never start, which is every command
// package: jsautomation.Manager.Invoke refuses one from a token outright.
//
// Filtered rather than listed-and-refused for the reason Registry.List gives for hiding an
// ungranted capability — advertising something denied on every call spends the model's
// context to buy it a wasted call and a confusing error. It also keeps the argv of the
// operator's local tooling out of an agent's context, which is worth having on its own.
func invokable(all []jsautomation.Summary) []jsautomation.Summary {
	out := make([]jsautomation.Summary, 0, len(all))
	for _, a := range all {
		if a.Kind == jsautomation.KindCommand {
			continue
		}
		out = append(out, a)
	}
	return out
}

func storeError(err error, other string) error {
	switch {
	case errors.Is(err, jsautomation.ErrEnabled), errors.Is(err, jsautomation.ErrTooManyPackages),
		errors.Is(err, jsautomation.ErrCommandNotSubmittable), errors.Is(err, jsautomation.ErrCommandNotInvokable):
		return &capability.Error{Code: capability.CodeForbidden, Msg: err.Error()}
	case errors.Is(err, jsautomation.ErrExists), errors.Is(err, jsautomation.ErrNotFound):
		return &capability.Error{
			Code: capability.CodeInvalidArgs,
			Msg:  fmt.Sprintf("%s; use %s", err.Error(), other),
		}
	case err == jsautomation.ErrHashMismatch:
		// Compared rather than errors.Is'd, deliberately: the store also wraps this
		// sentinel for a hash that was never stated, and that message already says what
		// to supply. Only the bare mismatch needs telling where the current hash is.
		return &capability.Error{
			Code: capability.CodeInvalidArgs,
			Msg:  fmt.Sprintf("%s: re-read it with script_list and retry with the hash it reports", err.Error()),
		}
	case err != nil:
		// Everything left from the store's front half is a fixable argument: a bad id, an
		// over-long field, a source over the operator's program-size limit, or a syntax
		// error the compile caught. Those messages name the field and the rule already.
		var ce *capability.Error
		if errors.As(err, &ce) {
			return err
		}
		return &capability.Error{Code: capability.CodeInvalidArgs, Msg: err.Error()}
	}
	return nil
}

// announceStored pushes the one event the Automations panel needs. It loads on mount and
// after its own actions and nothing else, so a package stored while the operator is
// looking at that panel would otherwise be invisible until they left it and came back.
//
// Droppable, like every capability broadcast: a stale panel is better than a handler that
// stalls on a full hub channel.
func announceStored(d Deps, a *jsautomation.Automation, p capability.Principal, created bool) {
	broadcast(d, "automation.script.stored", map[string]any{
		"id":         a.Manifest.ID,
		"name":       a.Manifest.Name,
		"version":    a.Manifest.Version,
		"sourceHash": a.SourceHash,
		"author":     storedBy(p),
		"created":    created,
	})
}

// renderStored tells the caller what it just gave up control of. Every line is something a
// caller gets wrong otherwise: that this armed nothing, that the triggers it declared are
// inert until the operator acts, and what it would take to change the code again.
func renderStored(a *jsautomation.Automation, replaced bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s v%s  %d bytes  sha256:%s\n",
		pick(replaced, "replaced", "stored"), a.Manifest.ID, a.Manifest.Version,
		len(a.Source), short(a.SourceHash))
	fmt.Fprintf(&b, "state: disabled — script_invoke refuses it until the operator enables it\n")
	fmt.Fprintf(&b, "triggers declared: %s (not armed)\n", joinOr(a.Manifest.Triggers, "-"))
	b.WriteString("the operator can read, edit, enable or remove it in Settings → Automation; " +
		"script_replace can change the code while it stays disabled")
	return b.String()
}

// short is the hash prefix these reports quote, in one place so the run report and the
// store reports cite the same number of characters.
func short(hash string) string {
	if len(hash) > 16 {
		return hash[:16]
	}
	return hash
}

// renderAutomations lists installed automations, one per line with aligned columns —
// the shape the other list tools use, and cheap to scan for the id to invoke.
func renderAutomations(items []jsautomation.Summary) string {
	if len(items) == 0 {
		return "(no automations installed)"
	}

	rows := make([][3]string, 0, len(items))
	var idW, verW int
	for _, a := range items {
		state := "disabled"
		switch {
		case a.Paused:
			state = "paused"
		case a.Enabled:
			state = "enabled"
		}
		armed := joinOr(a.Armed, "-")
		last := "never"
		if a.LastRun != nil {
			last = a.LastRun.Outcome
		}
		rows = append(rows, [3]string{a.ID, a.Version, fmt.Sprintf("%-8s armed=%s last=%s  %s",
			state, armed, last, a.Name)})
		idW = max(idW, len(a.ID))
		verW = max(verW, len(a.Version))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "n=%d\n", len(items))
	for _, r := range rows {
		fmt.Fprintf(&b, "%-*s  %-*s  %s\n", idW, r[0], verW, r[1], r[2])
	}
	return strings.TrimRight(b.String(), "\n")
}

// renderRun formats a run for the caller: a header, then logs, then the value.
//
// A single heterogeneous object, so this is a compact block rather than a table — but
// it still follows the encoding rule's spirit, in that the header names units once and
// nothing is repeated per line.
func renderRun(run *jsautomation.Run, logCap, resultCap int) string {
	res := run.Result
	var b strings.Builder

	// Both the prose and the code. The prose is what an operator reading the same block
	// in Activity sees, and the code is what the caller should branch on — worth the few
	// tokens, because a model comparing against reworded prose is the failure this pair
	// exists to prevent.
	fmt.Fprintf(&b, "run %s  outcome=%s (%s)  %dms\n", run.ID, res.Outcome, res.Reason, res.DurationMs)
	// Against the budget, not bare counts: the tool schema advertises the ceilings this
	// capability accepts, but the operator's global budget can be lower and is editable
	// while the registry is sealed — so this is where a caller learns what it actually
	// got, and it is enough to correct the next call by.
	fmt.Fprintf(&b, "sdk calls: %d/%d (%d/%d sending)   sdk bytes: %d in / %d out\n",
		res.Calls, res.Budget.MaxCalls, res.SendCalls, res.Budget.MaxSendCalls,
		res.CallInputBytes, res.CallOutputBytes)
	fmt.Fprintf(&b, "bundle: %s   source: sha256:%s\n", run.Bundle, short(run.SourceHash))
	// The same argument as the budget line above, for the other half of what a run was
	// held to. A run inherits its policy rather than asking for one, so this is the only
	// place a caller learns which posture refused its sends.
	fmt.Fprintf(&b, "policy: scope %s, credentials %s\n",
		pick(run.RequireScope, "required", "exempt"), pick(run.Credentials, "visible", "masked"))

	if res.Err != "" {
		b.WriteString("\n")
		b.WriteString(res.Err)
		b.WriteString("\n")
	}

	if len(res.Logs) > 0 {
		fmt.Fprintf(&b, "\nlogs (%d)\n", len(res.Logs))
		written := 0
		for _, l := range res.Logs {
			line := fmt.Sprintf("  %-5s %s\n", l.Level, oneLine(l.Text))
			if written+len(line) > logCap {
				b.WriteString("  … log output truncated\n")
				break
			}
			b.WriteString(line)
			written += len(line)
		}
		if res.LogsTruncated {
			b.WriteString("  … the run exceeded its log budget; later output was discarded\n")
		}
	}

	if len(res.Value) > 0 {
		b.WriteString("\nresult\n")
		if len(res.Value) > resultCap {
			b.WriteString(string(res.Value[:resultCap]))
			b.WriteString("\n… result truncated\n")
		} else {
			b.Write(res.Value)
			b.WriteString("\n")
		}
	} else if res.Reason == jsruntime.ReasonSuccess {
		b.WriteString("\nresult\n(run() returned nothing)\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

// pick returns one of two labels. Named states rather than a bare bool: "scope exempt"
// tells a reader what happened, where "requireScope: false" makes them work it out.
func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// oneLine keeps a multi-line log message from breaking the one-record-per-line shape
// the caller is reading. Escaped rather than dropped: a stack trace in a log line is
// worth keeping, and the escape is legible.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\\n")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return strings.ReplaceAll(s, "\t", "\\t")
}
