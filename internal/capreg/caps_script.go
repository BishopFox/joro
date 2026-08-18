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
}

type scriptRunArgs struct {
	Source string          `json:"source"`
	Input  json.RawMessage `json:"input"`

	TimeoutMs    int `json:"timeoutMs"`
	MaxCalls     int `json:"maxCalls"`
	MaxSendCalls int `json:"maxSendCalls"`
}

// Output shaping for the tool result.
//
// The logs and the returned value both have to fit inside this capability's output cap,
// and the cap is enforced after marshalling by erroring rather than truncating — so a
// script that logged generously would fail wholesale and the operator would lose the
// result along with the logs. These ceilings are therefore set below the runtime's own
// defaults and leave room for the header, and the renderer truncates again as a backstop.
const (
	scriptRunOutputCap = 256 << 10
	scriptLogBytes     = 64 << 10
	scriptResultBytes  = 96 << 10

	// scriptRunTimeout must exceed the longest run the arguments can ask for, so the
	// tool reports a real termination reason instead of the registry's bare timeout.
	// Same reasoning as http.resend's 70s over a 60s per-request maximum.
	scriptRunTimeout = 70 * time.Second
)

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
			"wall-clock deadline; console.log output and the return value both come back to you.",

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
      "type":"integer","minimum":1000,"maximum":60000,
      "description":"Wall-clock limit for the run. Default 25000."
    },
    "maxCalls": {
      "type":"integer","minimum":1,"maximum":500,
      "description":"Maximum SDK calls the run may make. Default 100."
    },
    "maxSendCalls": {
      "type":"integer","minimum":1,"maximum":100,
      "description":"Maximum SDK calls that put bytes on the wire. Default 25. Counted in addition to maxCalls, so a sending call spends one of each."
    }
  },
  "required":["source"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"source":"async function run(ctx) {\n  const base = await joro.http.fingerprint({ ref: ctx.input.ref });\n  return { base: base };\n}","input":{"ref":1842}}`),

		MaxOutputBytes: scriptRunOutputCap,
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

			run, err := d.Script.Run(ctx, jsautomation.RunRequest{
				Source:  args.Source,
				Input:   args.Input,
				Caller:  p,
				Trigger: "mcp",
				Limits: jsruntime.Limits{
					Timeout:        time.Duration(args.TimeoutMs) * time.Millisecond,
					MaxCalls:       args.MaxCalls,
					MaxSendCalls:   args.MaxSendCalls,
					MaxLogBytes:    scriptLogBytes,
					MaxResultBytes: scriptResultBytes,
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

			return renderRun(run), nil
		}),
	})
}

// renderRun formats a run for the caller: a header, then logs, then the value.
//
// A single heterogeneous object, so this is a compact block rather than a table — but
// it still follows the encoding rule's spirit, in that the header names units once and
// nothing is repeated per line.
func renderRun(run *jsautomation.Run) string {
	res := run.Result
	var b strings.Builder

	fmt.Fprintf(&b, "run %s  %s  %dms\n", run.ID, res.Reason, res.DurationMs)
	fmt.Fprintf(&b, "sdk calls: %d (%d sending)   sdk bytes: %d in / %d out\n",
		res.Calls, res.SendCalls, res.CallInputBytes, res.CallOutputBytes)
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
			if written+len(line) > scriptLogBytes {
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
		if len(res.Value) > scriptResultBytes {
			b.WriteString(string(res.Value[:scriptResultBytes]))
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
