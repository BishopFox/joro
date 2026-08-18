package jsruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// Tuning constants for the in-process VM.
const (
	// maxCallStackSize bounds JavaScript recursion. goja's default is high enough
	// that a runaway recursion allocates a large amount of Go heap before it
	// throws; a low ceiling turns that into a prompt RangeError the script can
	// even catch. High enough for any legitimate recursive walk.
	maxCallStackSize = 2048

	// memoryPollInterval is how often the heap is sampled. runtime.ReadMemStats
	// stops the world briefly, so this trades a small, fixed overhead for bounding
	// how much a script can allocate between checks.
	memoryPollInterval = 50 * time.Millisecond

	// maxLogLines caps the line count independently of MaxLogBytes, because a
	// million one-byte lines cost far more in slice overhead than in bytes.
	maxLogLines = 2000

	// maxErrDetail bounds a reported exception, stack trace included. Generous:
	// the stack is the most useful thing a model gets back when its own script
	// throws, and truncating it to a single line would cost a debugging round trip.
	maxErrDetail = 4096
)

// halt is the value passed to goja's Interrupt, so the reason a run was stopped
// survives as a typed value rather than being parsed back out of a message.
type halt struct {
	reason string
	detail string
}

// VM runs JavaScript with goja in the calling process.
//
// Terminating a run means interrupting the VM, which goja honors at loop back-edges
// and calls — reliable for computation, and the reason a plain interrupt is enough for
// timeouts. It is not enough for memory: goja has no allocation ceiling of any kind,
// so the heap is sampled and the VM interrupted on breach. That check is a mitigation,
// not a guarantee, because a single expression can allocate past the ceiling between
// two samples.
//
// Which is why Joro does not use this type directly for untrusted code. It is the
// engine WorkerRuntime drives inside a process whose death costs nothing.
type VM struct{}

// New returns an in-process runtime.
func New() *VM { return &VM{} }

var (
	shimOnce sync.Once
	shimProg *goja.Program
	shimErr  error
)

func compiledShim() (*goja.Program, error) {
	shimOnce.Do(func() {
		shimProg, shimErr = goja.Compile("joro-sdk.js", shimSource(), true)
	})
	return shimProg, shimErr
}

// logSink accumulates console output under a byte and line ceiling.
type logSink struct {
	maxBytes  int
	used      int
	lines     []LogLine
	truncated bool
}

func (s *logSink) add(level, text string) {
	if s.truncated {
		return
	}
	if len(s.lines) >= maxLogLines || s.used+len(text) > s.maxBytes {
		s.truncated = true
		return
	}
	s.used += len(text)
	s.lines = append(s.lines, LogLine{
		At:    time.Now().UTC().Format(time.RFC3339Nano),
		Level: level,
		Text:  text,
	})
}

// Run executes one program. The returned error is reserved for a failure of the
// runtime itself; everything the script does or fails to do — a syntax error, a
// throw, a timeout, an exhausted budget — comes back as a Result with a reason, so a
// caller has exactly one thing to report.
func (v *VM) Run(ctx context.Context, req Request, bridge HostBridge) (res Result, err error) {
	lim := req.Limits.Normalize()
	start := time.Now()
	sink := &logSink{maxBytes: lim.MaxLogBytes}

	finish := func(r Result) (Result, error) {
		r.Logs = sink.lines
		r.LogsTruncated = sink.truncated
		r.DurationMs = time.Since(start).Milliseconds()
		return r, nil
	}

	prepared, perr := Prepare(req.Source)
	if perr != nil {
		return finish(Result{Reason: ReasonRuntimeFailure, Err: perr.Error()})
	}

	shim, serr := compiledShim()
	if serr != nil {
		return Result{}, fmt.Errorf("compiling the SDK shim: %w", serr)
	}

	userProg, cerr := goja.Compile("automation.js", prepared, true)
	if cerr != nil {
		return finish(Result{
			Reason: ReasonRuntimeFailure,
			Err:    "syntax error: " + cerr.Error(),
		})
	}

	vm := goja.New()
	vm.SetMaxCallStackSize(maxCallStackSize)

	// Counters and the denial record, all touched only from the VM goroutine (host
	// functions run synchronously on it) except halted, which the watchdog writes.
	var (
		calls, sendCalls          int
		callInBytes, callOutBytes int
		deniedCodes               = map[string]bool{}
		halted                    halt
		haltedMu                  sync.Mutex
	)
	setHalt := func(h halt) {
		haltedMu.Lock()
		if halted.reason == "" {
			halted = h
		}
		haltedMu.Unlock()
		vm.Interrupt(h)
	}
	readHalt := func() halt {
		haltedMu.Lock()
		defer haltedMu.Unlock()
		return halted
	}

	sendCaps := make(map[string]struct{}, len(req.SendCaps))
	for _, id := range req.SendCaps {
		sendCaps[id] = struct{}{}
	}

	// The single host entry point. Only strings cross it, in both directions: a Go
	// error returned to goja would be wrapped in a GoError whose value is a
	// reflected Go object, handing the script exactly the kind of host handle this
	// package exists to withhold. Failures come back as a JSON envelope the shim
	// turns into a JavaScript throw.
	invoke := func(id string, argsJSON string) string {
		if h := readHalt(); h.reason != "" {
			return errEnvelope("halted", "the run has been stopped")
		}

		if calls >= lim.MaxCalls {
			setHalt(halt{reason: ReasonBudget, detail: fmt.Sprintf(
				"this run reached its limit of %d SDK calls", lim.MaxCalls)})
			return errEnvelope("budget_exceeded", fmt.Sprintf(
				"this run reached its limit of %d SDK calls; use joro.http.batch for bulk work", lim.MaxCalls))
		}
		_, isSend := sendCaps[id]
		if isSend && sendCalls >= lim.MaxSendCalls {
			setHalt(halt{reason: ReasonBudget, detail: fmt.Sprintf(
				"this run reached its limit of %d send-capable SDK calls", lim.MaxSendCalls)})
			return errEnvelope("budget_exceeded", fmt.Sprintf(
				"this run reached its limit of %d send-capable SDK calls; use joro.http.batch to send many "+
					"variants in one call", lim.MaxSendCalls))
		}
		if callInBytes+len(argsJSON) > lim.MaxCallInputBytes {
			setHalt(halt{reason: ReasonBudget, detail: "this run reached its cumulative SDK input limit"})
			return errEnvelope("budget_exceeded", fmt.Sprintf(
				"this run reached its cumulative SDK input limit of %d bytes", lim.MaxCallInputBytes))
		}

		if !json.Valid([]byte(argsJSON)) {
			// JSON.stringify yields undefined for a function or a symbol, which
			// arrives here as the literal "undefined". Naming the likely cause is
			// worth more to a model than "invalid JSON".
			return errEnvelope("invalid_args", "arguments did not serialize to JSON: pass a plain object "+
				"of JSON values, not a function, symbol, or object with a cycle")
		}

		calls++
		if isSend {
			sendCalls++
		}
		callInBytes += len(argsJSON)

		out, ierr := bridge.Invoke(ctx, id, json.RawMessage(argsJSON))
		if ierr != nil {
			var ce *CallError
			if e, ok := ierr.(*CallError); ok {
				ce = e
			} else {
				ce = &CallError{Code: "handler_error", Msg: ierr.Error()}
			}
			if ce.Denied && ce.Code != "" {
				deniedCodes[ce.Code] = true
			}
			return errEnvelope(ce.Code, ce.Msg)
		}

		callOutBytes += len(out)
		if callOutBytes > lim.MaxCallOutputBytes {
			setHalt(halt{reason: ReasonBudget, detail: "this run reached its cumulative SDK output limit"})
			return errEnvelope("budget_exceeded", fmt.Sprintf(
				"this run reached its cumulative SDK output limit of %d bytes; narrow the ranges or "+
					"filters you request", lim.MaxCallOutputBytes))
		}
		return okEnvelope(out)
	}

	if err := vm.Set("__joro_invoke", invoke); err != nil {
		return Result{}, fmt.Errorf("installing the host bridge: %w", err)
	}
	if err := vm.Set("__joro_log", func(level, text string) { sink.add(level, text) }); err != nil {
		return Result{}, fmt.Errorf("installing console capture: %w", err)
	}
	if _, err := vm.RunProgram(shim); err != nil {
		return Result{}, fmt.Errorf("initializing the SDK: %w", err)
	}

	// Entry resolution runs as a trailing statement in the user's own script rather
	// than by reading a global, so it sees a `const run = async () => {}` in the
	// global lexical scope, which never becomes a property of globalThis.
	var entry goja.Value
	if err := vm.Set("__joro_entry", func(v goja.Value) { entry = v }); err != nil {
		return Result{}, fmt.Errorf("installing the entry hook: %w", err)
	}
	entryProg, eerr := goja.Compile("joro-entry.js", `__joro_entry(typeof run === "function" ? run : undefined);`, true)
	if eerr != nil {
		return Result{}, fmt.Errorf("compiling the entry hook: %w", eerr)
	}

	// Watchdogs. Stopped before any post-run inspection so a late interrupt cannot
	// land on the VM while the result is being read out.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		deadline := time.NewTimer(lim.Timeout)
		defer deadline.Stop()
		poll := time.NewTicker(memoryPollInterval)
		defer poll.Stop()

		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		baseline := ms.HeapAlloc

		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				setHalt(halt{reason: ReasonCancelled, detail: "the run was cancelled"})
				return
			case <-deadline.C:
				setHalt(halt{reason: ReasonTimeout, detail: fmt.Sprintf(
					"the run exceeded its %s limit", lim.Timeout)})
				return
			case <-poll.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > baseline+uint64(lim.MemoryBytes) {
					setHalt(halt{reason: ReasonMemoryLimit, detail: fmt.Sprintf(
						"the run exceeded its %d MB memory limit", lim.MemoryBytes>>20)})
					return
				}
			}
		}
	})
	stopWatchdogs := func() {
		close(stop)
		wg.Wait()
	}

	// Phase 1: run the script body, which defines the entry point.
	_, rerr := vm.RunProgram(userProg)
	if rerr == nil {
		_, rerr = vm.RunProgram(entryProg)
	}
	vm.GlobalObject().Delete("__joro_entry")

	if rerr != nil {
		stopWatchdogs()
		return finish(v.failure(rerr, readHalt(), deniedCodes, calls, sendCalls, callInBytes, callOutBytes))
	}

	fn, ok := goja.AssertFunction(entry)
	if !ok {
		stopWatchdogs()
		return finish(Result{
			Reason: ReasonRuntimeFailure,
			Err: "no entry point: define `async function run(ctx) { ... }` at the top level. " +
				"The value returned from run() is the result of the automation.",
			Calls: calls, SendCalls: sendCalls,
			CallInputBytes: callInBytes, CallOutputBytes: callOutBytes,
		})
	}

	// Phase 2: call it.
	ctxArg, cerr2 := buildRunContext(vm, req)
	if cerr2 != nil {
		stopWatchdogs()
		return finish(Result{Reason: ReasonRuntimeFailure, Err: cerr2.Error()})
	}

	out, ferr := fn(goja.Undefined(), ctxArg)
	if ferr != nil {
		stopWatchdogs()
		return finish(v.failure(ferr, readHalt(), deniedCodes, calls, sendCalls, callInBytes, callOutBytes))
	}

	// An async function returns a promise. Every SDK call is synchronous, so a
	// promise whose awaits all resolve from SDK calls or settled values is already
	// settled by the time the call returns, and goja has drained its job queue.
	settled := out
	if p, isPromise := out.Export().(*goja.Promise); isPromise {
		switch p.State() {
		case goja.PromiseStateFulfilled:
			settled = p.Result()
		case goja.PromiseStateRejected:
			stopWatchdogs()
			// No Go error here: a rejected promise is not a goja error value, so the
			// rejection itself is what failure reports on.
			return finish(v.failure(
				nil, readHalt(), deniedCodes, calls, sendCalls, callInBytes, callOutBytes,
				withRejection(vm, p.Result())))
		default:
			stopWatchdogs()
			return finish(Result{
				Reason: ReasonException,
				Err: "run() returned a promise that never settled. The sandbox has no timers, sockets " +
					"or filesystem, so every await must resolve from an SDK call or an already-settled " +
					"value — an await on `new Promise(...)` that nothing resolves will hang here.",
				Calls: calls, SendCalls: sendCalls,
				CallInputBytes: callInBytes, CallOutputBytes: callOutBytes,
			})
		}
	}

	stopWatchdogs()

	if h := readHalt(); h.reason != "" {
		return finish(Result{
			Reason: h.reason, Err: h.detail,
			Calls: calls, SendCalls: sendCalls,
			CallInputBytes: callInBytes, CallOutputBytes: callOutBytes,
		})
	}

	value, verr := marshalResult(settled, lim.MaxResultBytes)
	if verr != nil {
		return finish(Result{
			Reason: ReasonRuntimeFailure, Err: verr.Error(),
			Calls: calls, SendCalls: sendCalls,
			CallInputBytes: callInBytes, CallOutputBytes: callOutBytes,
		})
	}

	return finish(Result{
		Reason: ReasonSuccess, Value: value,
		Calls: calls, SendCalls: sendCalls,
		CallInputBytes: callInBytes, CallOutputBytes: callOutBytes,
	})
}

// rejection carries a promise rejection value through to failure reporting.
type rejection struct {
	text string
	code string
}

func withRejection(vm *goja.Runtime, v goja.Value) *rejection {
	text, code := describeThrown(vm, v)
	return &rejection{text: text, code: code}
}

// failure maps a goja error into a Result. A halt always wins over the script's own
// error: when a run is interrupted, goja surfaces an InterruptedError, but the script
// may also have been mid-throw, and the operator needs to be told it was stopped
// rather than that it failed.
func (v *VM) failure(
	gerr error, h halt, deniedCodes map[string]bool,
	calls, sendCalls, inBytes, outBytes int,
	rej ...*rejection,
) Result {
	res := Result{
		Calls: calls, SendCalls: sendCalls,
		CallInputBytes: inBytes, CallOutputBytes: outBytes,
	}

	if h.reason != "" {
		res.Reason = h.reason
		res.Err = h.detail
		return res
	}

	if ie, ok := gerr.(*goja.InterruptedError); ok {
		if hv, ok := ie.Value().(halt); ok {
			res.Reason = hv.reason
			res.Err = hv.detail
			return res
		}
		res.Reason = ReasonCancelled
		res.Err = "the run was interrupted"
		return res
	}

	res.Reason = ReasonException
	switch {
	case len(rej) > 0 && rej[0] != nil:
		res.Err = rej[0].text
		if deniedCodes[rej[0].code] {
			res.Reason = ReasonDenied
		}

	default:
		// A stack overflow is an Exception whose value has no message, so the generic
		// path would report a bare stack with nothing saying what went wrong.
		var so *goja.StackOverflowError
		if errors.As(gerr, &so) {
			res.Err = trunc("RangeError: maximum call stack size exceeded — the script recursed "+
				"deeper than "+strconv.Itoa(maxCallStackSize)+" frames\n"+so.String(), maxErrDetail)
			return res
		}
		if exc, ok := gerr.(*goja.Exception); ok {
			text, code := describeThrown(nil, exc.Value())
			if text == "" {
				text = trunc(exc.String(), maxErrDetail)
			}
			res.Err = text
			if deniedCodes[code] {
				res.Reason = ReasonDenied
			}
		} else {
			res.Err = trunc(gerr.Error(), maxErrDetail)
		}
	}
	if res.Err == "" {
		res.Err = "the script threw a value with no message"
	}
	return res
}

// describeThrown renders a thrown JavaScript value and extracts its code property, if
// it has one. Reading named properties off an object is not the same as exporting it:
// nothing goja-owned escapes into the host.
func describeThrown(_ *goja.Runtime, v goja.Value) (text, code string) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return "", ""
	}
	obj := v.ToObject(nil)
	if obj == nil {
		return trunc(v.String(), maxErrDetail), ""
	}
	get := func(k string) string {
		pv := obj.Get(k)
		if pv == nil || goja.IsUndefined(pv) || goja.IsNull(pv) {
			return ""
		}
		return pv.String()
	}
	name, msg := get("name"), get("message")
	code = get("code")
	if name == "" && msg == "" && code == "" {
		// Not an Error at all — a thrown string, number or bare object.
		return trunc(v.String(), maxErrDetail), ""
	}

	header := orDefault(name, "Error")
	if msg != "" {
		header += ": " + msg
	}
	full := header
	if code != "" {
		full += " [" + code + "]"
	}

	// goja's stack property already begins with "Name: message", so splicing the code
	// into that first line reads as one error with a trace, where concatenating would
	// print the message twice.
	if st := get("stack"); st != "" {
		if rest, ok := strings.CutPrefix(st, header); ok {
			return trunc(full+rest, maxErrDetail), code
		}
		return trunc(full+"\n"+st, maxErrDetail), code
	}
	return trunc(full, maxErrDetail), code
}

// buildRunContext assembles the ctx argument. Meta round-trips through JSON so the
// value handed to the VM is built from plain maps and slices — goja binds the methods
// and exported fields of a Go struct automatically, and a struct passed here would
// give the script a reflected handle on a host type.
func buildRunContext(vm *goja.Runtime, req Request) (goja.Value, error) {
	var input any
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("run input is not valid JSON: %v", err)
		}
	}

	m := req.Meta
	run := map[string]any{"id": m.RunID, "startedAt": m.StartedAt}
	ctxObj := map[string]any{
		"run":     run,
		"trigger": map[string]any{"type": orDefault(m.TriggerType, "manual")},
		"input":   input,
	}
	if m.AutomationID != "" {
		ctxObj["automation"] = map[string]any{"id": m.AutomationID, "version": m.AutomationVersion}
	}
	return vm.ToValue(ctxObj), nil
}

// marshalResult serializes run()'s return value under the result ceiling.
func marshalResult(v goja.Value, maxBytes int) (json.RawMessage, error) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil, nil
	}
	exported := v.Export()
	// A function, or an object holding one, has no JSON form. Reporting that
	// plainly beats the encoder's "unsupported type" against an internal type name.
	encoded, err := json.Marshal(exported)
	if err != nil {
		return nil, fmt.Errorf("the value returned from run() is not JSON-serializable (%v). "+
			"Return plain objects, arrays, strings and numbers", err)
	}
	if len(encoded) > maxBytes {
		return nil, fmt.Errorf("the value returned from run() is %d bytes, over the %d byte limit. "+
			"Return a summary and keep bulk data out of the result", len(encoded), maxBytes)
	}
	return encoded, nil
}

// okEnvelope and errEnvelope build the JSON the shim expects. ok wraps the
// capability's own JSON by concatenation, so a result is never re-encoded and cannot
// be altered on the way through.
func okEnvelope(data json.RawMessage) string {
	if len(data) == 0 {
		return `{"ok":true}`
	}
	var b strings.Builder
	b.Grow(len(data) + 16)
	b.WriteString(`{"ok":true,"data":`)
	b.Write(data)
	b.WriteString(`}`)
	return b.String()
}

func errEnvelope(code, msg string) string {
	payload := struct {
		OK      bool   `json:"ok"`
		Code    string `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
	}{OK: false, Code: code, Message: msg}
	out, err := json.Marshal(payload)
	if err != nil {
		return `{"ok":false,"code":"handler_error","message":"the failure could not be encoded"}`
	}
	return string(out)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
