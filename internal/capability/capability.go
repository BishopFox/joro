// Package capability is the authorization layer for Joro's automation surface.
//
// Every operation exposed to an automation client is registered exactly once as a
// Capability, and every invocation goes through Registry.Invoke, which applies
// authorization, scope, rate and concurrency limits, an output-size cap, and an
// audit record. A consumer (the MCP server) never calls a handler directly, so
// there is no path that skips the guard.
//
// This package is pure policy. It imports no other internal package: it defines
// ScopeChecker rather than importing internal/proxy, and it defines Principal
// rather than importing internal/automation. The second of those is load-bearing —
// because internal/automation imports this package, Go's import-cycle rule makes it
// impossible for code here to reach the token store. Grant administration is
// therefore not merely un-registered as a capability, it is unreachable from one.
// See reserved.go for the rest of that argument.
package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"
)

// Class groups capabilities for the grant picker. It is presentation and policy,
// not dispatch: nothing keys behavior off a Class except the scope/mutating rule
// enforced in Register.
type Class string

const (
	ClassInstance  Class = "instance"
	ClassHistory   Class = "history"
	ClassSitemap   Class = "sitemap"
	ClassScope     Class = "scope"
	ClassFindings  Class = "findings"
	ClassNotes     Class = "notes"
	ClassHTTP      Class = "http"
	ClassWebSocket Class = "websocket"
	ClassFuzzer    Class = "fuzzer"
	ClassContext   Class = "context"
	ClassConfig    Class = "config"
	ClassDetect    Class = "detect"
	ClassExec      Class = "exec"
	ClassC2        Class = "c2"
)

// Classes lists every valid class, in the order the grant picker shows them. The
// order is load-bearing now that write-heavy classes exist: sorting by ID instead
// would put config and detect at the top of the picker, leading with the groups an
// operator should consider last.
var Classes = []Class{
	ClassInstance, ClassHistory, ClassSitemap, ClassScope, ClassFindings, ClassNotes,
	ClassHTTP, ClassWebSocket, ClassFuzzer, ClassContext, ClassConfig, ClassDetect,
	ClassExec, ClassC2,
}

func validClass(c Class) bool { return slices.Contains(Classes, c) }

// Handler runs one capability. Handlers are not written directly — use Typed, which
// supplies the decode step and keeps the registry monomorphic.
type Handler func(ctx context.Context, in Input) (any, error)

// Input is what a handler receives. Args is the raw JSON the client supplied;
// Principal identifies the caller for handlers that need to record who acted.
type Input struct {
	Args      json.RawMessage
	Principal Principal
}

// Target is the destination of a capability that emits traffic. The registry
// extracts it from the arguments and evaluates the scope guard against it before
// any handler code runs.
type Target struct {
	Host   string
	Method string
	Path   string
}

// TargetExtractor derives the target of a send from its arguments. Required on any
// capability with SendsTraffic set; Register panics without one.
//
// It must not perform I/O beyond reading Joro's own capture store: it runs on the
// guard path, before authorization to send has been established.
type TargetExtractor func(args json.RawMessage) (Target, error)

// Capability is one operation exposed to automation.
type Capability struct {
	// ID is the stable, permanent name, "<class>.<verb>". Renaming one silently
	// un-grants it for every existing token, so treat it as an API commitment.
	// Must contain no underscore: MCP tool names are derived by replacing dots
	// with underscores, and the round trip is only total without them.
	ID    string
	Class Class

	// Title labels the capability in the grant picker. Description is model-facing
	// and becomes the MCP tool description — it is the contract text an agent reads,
	// so it should say what the tool returns and what it costs.
	Title       string
	Description string

	// Mutating reports that the capability changes Joro's own state.
	// SendsTraffic reports that it emits bytes to a target host, which is what
	// engages the scope guard. They are independent axes.
	Mutating     bool
	SendsTraffic bool

	// Privileged marks a capability that drives command execution or an operator's
	// C2. These are registered only when Joro is started with --automation-privileged,
	// and even then no profile grants one: the operator must select it by hand.
	//
	// The flag itself is not the gate — an unregistered capability cannot be granted,
	// listed or invoked at all. It exists so validateProfiles can refuse to bundle
	// one, the grant picker can mark it, and the audit log can record it.
	Privileged bool

	// UnrestrictedOnly refuses the capability to any token the operator has
	// leashed — one with RequireScope set, or with a non-empty HostAllow.
	//
	// It is mandatory on a mutating scope-class capability, and Register panics
	// without it. The reasoning is an asymmetry: a token whose authorization
	// control *is* scope must never edit scope, but a token the operator has
	// explicitly exempted from scope gains no reach by editing it — checkTarget
	// already admits every host for such a token, so there is no privilege to
	// escalate. See the guard rule in guard.go.
	UnrestrictedOnly bool

	// InputSchema is a hand-written JSON Schema object. ArgsExample must be a valid
	// instance of it and must decode through the handler's own decoder — that
	// pairing is what stops the schema and the Go struct drifting apart.
	InputSchema json.RawMessage
	ArgsExample json.RawMessage

	// MaxOutputBytes caps the marshalled result. Zero means DefaultMaxOutputBytes.
	// This is a blunt backstop; tools do their own truncation at a row or hunk
	// boundary so their output stays usable rather than merely small.
	MaxOutputBytes int

	// Timeout bounds one invocation. Zero means DefaultTimeout.
	Timeout time.Duration

	Handler Handler
	Target  TargetExtractor
}

// Defaults applied when a Capability leaves the field zero.
const (
	DefaultMaxOutputBytes = 1 << 20
	DefaultTimeout        = 30 * time.Second
)

func (c Capability) maxOutputBytes() int {
	if c.MaxOutputBytes > 0 {
		return c.MaxOutputBytes
	}
	return DefaultMaxOutputBytes
}

func (c Capability) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// Result is a successful invocation's outcome. Data is whatever the handler
// returned; Bytes is its marshalled size, recorded for the audit log.
type Result struct {
	Data     any
	Bytes    int
	Duration time.Duration
}

// Typed adapts a strongly-typed handler to the registry's untyped Handler, so the
// registry stays monomorphic while every handler body works on a real struct and
// argument decoding happens in exactly one place.
//
// DisallowUnknownFields is deliberate. The UI is a program that matches the server,
// but an automation client is a language model that invents arguments. Silently
// ignoring an invented "limit" would return an unbounded result set instead of the
// error the agent needs in order to correct itself.
func Typed[T any](fn func(ctx context.Context, p Principal, args T) (any, error)) Handler {
	return func(ctx context.Context, in Input) (any, error) {
		var args T
		if len(in.Args) > 0 && !bytes.Equal(bytes.TrimSpace(in.Args), []byte("null")) {
			dec := json.NewDecoder(bytes.NewReader(in.Args))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&args); err != nil {
				return nil, &Error{Code: CodeInvalidArgs, Msg: err.Error()}
			}
		}
		return fn(ctx, in.Principal, args)
	}
}

// TypedTarget mirrors Typed for target extraction. A decode failure here surfaces
// as invalid_args before the scope guard runs, which is correct: arguments that
// don't parse have no target to check.
func TypedTarget[T any](fn func(args T) (Target, error)) TargetExtractor {
	return func(raw json.RawMessage) (Target, error) {
		var args T
		if len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&args); err != nil {
				return Target{}, &Error{Code: CodeInvalidArgs, Msg: err.Error()}
			}
		}
		return fn(args)
	}
}
