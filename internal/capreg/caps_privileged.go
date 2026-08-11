package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/shell"
)

// Execution and C2. These are registered only when Joro is started with
// --automation-privileged, and no profile grants one even then.
//
// The containment differs between the two families and the descriptions say so.
// exec.webshell dials a web target, so it carries a Target extractor and the scope
// guard applies to it exactly as it does to http.resend. The c2 capabilities reach
// the operator's own team server, which scope rules do not describe — scope-guarding
// them would deny every call rather than bound anything — so the launch flag and the
// explicit grant are their whole control.

const maxWebshellCommand = 4 << 10

type webshellArgs struct {
	Target   string `json:"target"`
	Webshell string `json:"webshell"`
	AuthKey  string `json:"authKey"`
	Command  string `json:"command"`
}

type c2CommandArgs struct {
	Input string `json:"input"`
}

func registerPrivileged(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:           "exec.webshell",
		Class:        capability.ClassExec,
		Title:        "Run a command through a deployed web shell",
		Mutating:     true,
		Privileged:   true,
		SendsTraffic: true,
		Description: "Execute a shell command on a host through a web shell already deployed there, using the " +
			"auth key from when it was generated. Held to this token's scope and host whitelist. Output is " +
			"whatever the shell returns, truncated to the output cap.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":   {"type":"string","description":"Full URL of the deployed shell, e.g. \"https://target.example/uploads/s.php\"."},
    "webshell": {"type":"string","description":"Shell format: php, asp, aspx, ashx, jsp or cfm."},
    "authKey":  {"type":"string","description":"The auth key generated with the shell."},
    "command":  {"type":"string","description":"The command to run."}
  },
  "required":["target","webshell","authKey","command"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"target":"https://target.example/uploads/s.php","webshell":"php",` +
			`"authKey":"3f2a...","command":"id"}`),
		MaxOutputBytes: 64 << 10,
		Target: capability.TypedTarget(func(args webshellArgs) (capability.Target, error) {
			u, err := url.Parse(strings.TrimSpace(args.Target))
			if err != nil || u.Host == "" {
				return capability.Target{}, fmt.Errorf("target must be a full URL including scheme and host")
			}
			return capability.Target{Host: u.Host, Method: "POST", Path: u.Path}, nil
		}),
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args webshellArgs) (any, error) {
			if args.Target == "" || args.Webshell == "" || args.AuthKey == "" || args.Command == "" {
				return nil, fmt.Errorf("target, webshell, authKey and command are all required")
			}
			if len(args.Command) > maxWebshellCommand {
				return nil, fmt.Errorf("command is %d bytes, over the %d byte limit",
					len(args.Command), maxWebshellCommand)
			}
			client := proxy.NewHTTPClient("", d.Transport)
			out, err := shell.ExecuteCommand(args.Target, args.Webshell, args.AuthKey, args.Command, client)
			capability.RecordChange(ctx, "webshell exec on %s", args.Target)
			if err != nil {
				return nil, err
			}
			return out, nil
		}),
	})

	registerSliver(r, d)
	registerMythic(r, d)
}

func registerSliver(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:         "c2.sliver.read",
		Class:      capability.ClassC2,
		Privileged: true,
		Title:      "List Sliver sessions and beacons",
		Description: "Whether Joro is connected to a Sliver server, and the sessions and beacons it can see. " +
			"Read-only: it runs nothing on an implant.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 32 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Sliver == nil {
				return nil, fmt.Errorf("the Sliver client is unavailable")
			}
			if !d.Sliver.IsConnected() {
				return "not connected to a Sliver server", nil
			}
			var b strings.Builder
			b.WriteString("connected\n")
			sessions, err := d.Sliver.ListSessions(ctx)
			if err != nil {
				return nil, err
			}
			for _, s := range sessions {
				fmt.Fprintf(&b, "session %s %s %s/%s user=%s from=%s\n",
					s.ID, s.Hostname, s.OS, s.Arch, s.Username, s.RemoteAddress)
			}
			beacons, err := d.Sliver.ListBeacons(ctx)
			if err == nil {
				for _, bn := range beacons {
					fmt.Fprintf(&b, "beacon %s %s %s/%s\n", bn.ID, bn.Hostname, bn.OS, bn.Arch)
				}
			}
			if len(sessions) == 0 && len(beacons) == 0 {
				b.WriteString("(no sessions or beacons)")
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:         "c2.sliver.command",
		Class:      capability.ClassC2,
		Mutating:   true,
		Privileged: true,
		Title:      "Run a Sliver command",
		Description: "Issue a command to the connected Sliver server, in the same text form the Execute tab " +
			"accepts: `sessions`, `use <id>` to select an implant, then commands that run on it. Scope and " +
			"this token's host whitelist do not apply — they describe web targets, not a C2 server — so the " +
			"grant itself is the only limit on what this reaches. Binary results are cached for the operator " +
			"rather than returned.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "input": {"type":"string","description":"The command line, e.g. \"sessions\", \"use 3\", \"ls /tmp\"."}
  },
  "required":["input"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"input":"sessions"}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args c2CommandArgs) (any, error) {
			if d.Sliver == nil {
				return nil, fmt.Errorf("the Sliver client is unavailable")
			}
			input := strings.TrimSpace(args.Input)
			if input == "" {
				return nil, fmt.Errorf("input is required")
			}
			res := d.Sliver.Dispatch(ctx, input)
			capability.RecordChange(ctx, "sliver: %s", trunc(input, 120))
			return renderC2Result(res.Output, res.Error, res.Filename), nil
		}),
	})
}

func registerMythic(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:         "c2.mythic.read",
		Class:      capability.ClassC2,
		Privileged: true,
		Title:      "List Mythic callbacks",
		Description: "Whether Joro is connected to a Mythic server, and the callbacks it can see. Read-only: it " +
			"tasks nothing.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 32 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Mythic == nil {
				return nil, fmt.Errorf("the Mythic client is unavailable")
			}
			if !d.Mythic.IsConnected() {
				return "not connected to a Mythic server", nil
			}
			callbacks, err := d.Mythic.ListCallbacks(ctx)
			if err != nil {
				return nil, err
			}
			if len(callbacks) == 0 {
				return "connected\n(no callbacks)", nil
			}
			var b strings.Builder
			b.WriteString("connected\n")
			for _, c := range callbacks {
				fmt.Fprintf(&b, "callback %d %s@%s %s/%s ip=%s payload=%s\n",
					c.DisplayID, c.User, c.Host, c.OS, c.Architecture, c.IP, c.PayloadType)
			}
			return strings.TrimRight(b.String(), "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:         "c2.mythic.command",
		Class:      capability.ClassC2,
		Mutating:   true,
		Privileged: true,
		Title:      "Run a Mythic command",
		Description: "Issue a command to the connected Mythic server, in the same text form the Execute tab " +
			"accepts: `callbacks`, `use <display id>` to select one, then commands its agent has loaded. Scope " +
			"and this token's host whitelist do not apply — they describe web targets, not a C2 server — so the " +
			"grant itself is the only limit on what this reaches.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "input": {"type":"string","description":"The command line, e.g. \"callbacks\", \"use 4\", \"shell whoami\"."}
  },
  "required":["input"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"input":"callbacks"}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args c2CommandArgs) (any, error) {
			if d.Mythic == nil {
				return nil, fmt.Errorf("the Mythic client is unavailable")
			}
			input := strings.TrimSpace(args.Input)
			if input == "" {
				return nil, fmt.Errorf("input is required")
			}
			res := d.Mythic.Dispatch(ctx, input)
			capability.RecordChange(ctx, "mythic: %s", trunc(input, 120))
			return renderC2Result(res.Output, res.Error, res.Filename), nil
		}),
	})
}

// renderC2Result flattens a dispatcher result. A download is reported by name only:
// the bytes are cached server-side for the operator to retrieve from the UI, and
// pushing a binary through a tool result would be useless to a model and expensive.
func renderC2Result(output, errMsg, filename string) string {
	var b strings.Builder
	if output != "" {
		b.WriteString(output)
	}
	if filename != "" {
		fmt.Fprintf(&b, "\n[file %s is cached for the operator to download from the Execute tab]", filename)
	}
	if errMsg != "" {
		fmt.Fprintf(&b, "\nerror: %s", errMsg)
	}
	if b.Len() == 0 {
		return "(no output)"
	}
	return strings.TrimSpace(b.String())
}
