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
			"There is no network, filesystem, process or module access — joro is the only way out, and " +
			"credential headers are masked in everything it returns. Each run has its own request budget and " +
			"wall-clock deadline, both set by the operator and possibly above or below the maxima here; ask " +
			"for what you need, and read your result for what you were actually given. console.log output " +
			"and the return value both come back to you.",

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
		ArgsExample: json.RawMessage(`{"source":"async function run(ctx) {\n  const base = await joro.http.fingerprint({ ref: ctx.input.ref });\n  return { base: base };\n}","input":{"ref":1842}}`),

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
			return renderAutomations(d.Script.List()), nil
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
		ArgsExample: json.RawMessage(`{"id":"idor-check","input":{"ref":1842}}`),

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
			case errors.Is(err, jsautomation.ErrNotFound):
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
			last = a.LastRun.Reason
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

	fmt.Fprintf(&b, "run %s  %s  %dms\n", run.ID, res.Reason, res.DurationMs)
	// Against the budget, not bare counts: the tool schema advertises the ceilings this
	// capability accepts, but the operator's global budget can be lower and is editable
	// while the registry is sealed — so this is where a caller learns what it actually
	// got, and it is enough to correct the next call by.
	fmt.Fprintf(&b, "sdk calls: %d/%d (%d/%d sending)   sdk bytes: %d in / %d out\n",
		res.Calls, res.Budget.MaxCalls, res.SendCalls, res.Budget.MaxSendCalls,
		res.CallInputBytes, res.CallOutputBytes)
	fmt.Fprintf(&b, "bundle: %s   source: sha256:%s\n", run.Bundle, run.SourceHash[:16])

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

// oneLine keeps a multi-line log message from breaking the one-record-per-line shape
// the caller is reading. Escaped rather than dropped: a stack trace in a log line is
// worth keeping, and the escape is legible.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\\n")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return strings.ReplaceAll(s, "\t", "\\t")
}
