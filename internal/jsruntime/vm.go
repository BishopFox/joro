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

// Validate reports whether a program could be loaded at all: the module preamble must be
// erasable and the result must parse.
//
// It compiles without executing, which is what makes it safe to run in the parent process
// at install time. Catching a syntax error while whoever submitted the package is still
// looking at it beats surfacing it hours later as a trigger that quietly does nothing.
func Validate(source string, maxBytes int) error {
	prepared, err := Prepare(source, maxBytes)
	if err != nil {
		return err
	}
	if _, err := goja.Compile("automation.js", prepared, true); err != nil {
		return fmt.Errorf("syntax error: %v", err)
	}
	return nil
}

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
	lim := req.Limits.Fill()
	start := time.Now()
	sink := &logSink{maxBytes: lim.MaxLogBytes}

	// Per-run counters. Declared before finish so that one place stamps them onto every
	// Result, success or not — on a failure they are most of what explains it, and
	// repeating them at each return is how one gets forgotten.
	var (
		calls, sendCalls          int
		storageOps                int
		callInBytes, callOutBytes int
	)

	finish := func(r Result) (Result, error) {
		r.Logs = sink.lines
		r.LogsTruncated = sink.truncated
		r.Calls, r.SendCalls, r.StorageOps = calls, sendCalls, storageOps
		r.CallInputBytes, r.CallOutputBytes = callInBytes, callOutBytes
		r.Budget = lim.Budget()
		r.DurationMs = time.Since(start).Milliseconds()
		return r, nil
	}

	// Last resort. Every known path that touches a script-controlled value is wrapped in
	// vm.Try, but this package's whole job is to survive whatever the guest does, and a
	// panic escaping into the caller would be the one failure mode it cannot report. In
	// the worker that means a signal and a lost run; in-process it would take the proxy.
	defer func() {
		if rec := recover(); rec != nil {
			res, err = finish(Result{
				Reason: ReasonRuntimeFailure,
				Err:    fmt.Sprintf("the script runtime panicked: %v", rec),
			})
		}
	}()

	prepared, perr := Prepare(req.Source, lim.MaxSourceBytes)
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
		deniedCodes = map[string]bool{}
		halted      halt
		haltedMu    sync.Mutex
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

	// joro.storage. Present in the shim for every run; whether this run has a namespace
	// to store into is answered here, because only the host knows.
	storageFn := func(op, key, valueJSON string) string {
		sb, ok := bridge.(StorageBridge)
		if !ok {
			return errEnvelope("storage_unavailable", storageUnavailableMsg)
		}
		if h := readHalt(); h.reason != "" {
			return errEnvelope("halted", "the run has been stopped")
		}
		if storageOps >= lim.MaxStorageOps {
			setHalt(halt{reason: ReasonBudget, detail: fmt.Sprintf(
				"this run reached its limit of %d storage operations", lim.MaxStorageOps)})
			return errEnvelope("budget_exceeded", fmt.Sprintf(
				"this run reached its limit of %d storage operations", lim.MaxStorageOps))
		}
		storageOps++

		out, serr := sb.Storage(ctx, op, key, json.RawMessage(valueJSON))
		if serr != nil {
			var ce *CallError
			if errors.As(serr, &ce) {
				return errEnvelope(ce.Code, ce.Msg)
			}
			return errEnvelope("storage_error", serr.Error())
		}
		return okEnvelope(out)
	}

	if err := vm.Set("__joro_invoke", invoke); err != nil {
		return Result{}, fmt.Errorf("installing the host bridge: %w", err)
	}
	if err := vm.Set("__joro_storage", storageFn); err != nil {
		return Result{}, fmt.Errorf("installing the storage bridge: %w", err)
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

	// Watchdogs. Deliberately NOT stopped before the result is read out: rendering a
	// thrown value and exporting a returned one both run script code — a getter, a
	// toString, a toJSON — so those reads need the deadline and the memory sampler as
	// much as run() does. Every such read happens inside vm.Try, which turns a landing
	// interrupt into an error rather than a panic.
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
	defer stopWatchdogs()

	// Phase 1: run the script body, which defines the entry point.
	_, rerr := vm.RunProgram(userProg)
	if rerr == nil {
		_, rerr = vm.RunProgram(entryProg)
	}
	_ = vm.Try(func() { vm.GlobalObject().Delete("__joro_entry") })

	if rerr != nil {
		return finish(failure(vm, rerr, readHalt(), deniedCodes))
	}

	fn, ok := goja.AssertFunction(entry)
	if !ok {
		return finish(Result{
			Reason: ReasonRuntimeFailure,
			Err: "no entry point: define `async function run(ctx) { ... }` at the top level. " +
				"The value returned from run() is the result of the automation.",
		})
	}

	// Phase 2: call it.
	ctxArg, cerr2 := buildRunContext(vm, req)
	if cerr2 != nil {
		return finish(Result{Reason: ReasonRuntimeFailure, Err: cerr2.Error()})
	}

	out, ferr := fn(goja.Undefined(), ctxArg)
	if ferr != nil {
		return finish(failure(vm, ferr, readHalt(), deniedCodes))
	}

	// An async function returns a promise. Every SDK call is synchronous, so a
	// promise whose awaits all resolve from SDK calls or settled values is already
	// settled by the time the call returns, and goja has drained its job queue.
	//
	// Export is inside Try because it is not a passive read: for a plain object it walks
	// own enumerable properties and invokes their accessors, which is script code.
	settled := out
	var promise *goja.Promise
	if ex := vm.Try(func() { promise, _ = out.Export().(*goja.Promise) }); ex != nil {
		return finish(failure(vm, ex, readHalt(), deniedCodes))
	}
	if promise != nil {
		switch promise.State() {
		case goja.PromiseStateFulfilled:
			settled = promise.Result()
		case goja.PromiseStateRejected:
			// No Go error here: a rejected promise is not a goja error value, so the
			// rejection itself is what failure reports on.
			return finish(failure(
				vm, nil, readHalt(), deniedCodes, withRejection(vm, promise.Result())))
		default:
			return finish(Result{
				Reason: ReasonException,
				Err: "run() returned a promise that never settled. The sandbox has no timers, sockets " +
					"or filesystem, so every await must resolve from an SDK call or an already-settled " +
					"value — an await on `new Promise(...)` that nothing resolves will hang here.",
			})
		}
	}

	if h := readHalt(); h.reason != "" {
		return finish(Result{
			Reason: h.reason, Err: h.detail,
		})
	}

	value, verr := marshalResult(vm, settled, lim.MaxResultBytes)
	if verr != nil {
		return finish(Result{
			Reason: ReasonRuntimeFailure, Err: verr.Error(),
		})
	}

	return finish(Result{
		Reason: ReasonSuccess, Value: value,
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
// Counters are not passed in: finish stamps them onto whatever this returns. It takes the
// runtime because rendering the thrown value runs script code and needs one.
func failure(rt *goja.Runtime, gerr error, h halt, deniedCodes map[string]bool, rej ...*rejection) Result {
	var res Result

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
			text, code := describeThrown(rt, exc.Value())
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

// describeThrown renders a thrown JavaScript value and extracts its code property, if it
// has one.
//
// Every line of this touches script-controlled machinery, and none of it is a passive
// read. ToObject on a primitive allocates a wrapper *through the runtime* — which is why
// it must be given a real one rather than nil — and reading .name, .message, .code or
// .stack invokes whatever accessor the script defined, as does String() on an object with
// a toString. goja's own documentation says these panic with *Exception, so the whole body
// runs inside Try and a failure to render reports a fixed string rather than propagating.
func describeThrown(rt *goja.Runtime, v goja.Value) (text, code string) {
	if rt == nil || v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return "", ""
	}

	var name, msg, stack, raw string
	if ex := rt.Try(func() {
		raw = v.String()
		obj := v.ToObject(rt)
		if obj == nil {
			return
		}
		get := func(k string) string {
			pv := obj.Get(k)
			if pv == nil || goja.IsUndefined(pv) || goja.IsNull(pv) {
				return ""
			}
			return pv.String()
		}
		name, msg, code, stack = get("name"), get("message"), get("code"), get("stack")
	}); ex != nil {
		return "the thrown value could not be rendered: reading it threw", ""
	}

	if name == "" && msg == "" && code == "" {
		// Not an Error at all — a thrown string, number or bare object.
		return trunc(raw, maxErrDetail), ""
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
	if st := stack; st != "" {
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

	// The trigger payload is merged beside the type rather than nested under a "data"
	// key, so a script reads ctx.trigger.requests instead of ctx.trigger.data.requests.
	// "type" is written last so a payload cannot shadow it.
	trigger := map[string]any{}
	if len(m.TriggerData) > 0 {
		if err := json.Unmarshal(m.TriggerData, &trigger); err != nil {
			return nil, fmt.Errorf("trigger payload is not a JSON object: %v", err)
		}
	}
	trigger["type"] = orDefault(m.TriggerType, "manual")

	run := map[string]any{"id": m.RunID, "startedAt": m.StartedAt}
	ctxObj := map[string]any{
		"run":     run,
		"trigger": trigger,
		"input":   input,
	}
	if m.AutomationID != "" {
		ctxObj["automation"] = map[string]any{"id": m.AutomationID, "version": m.AutomationVersion}
	}
	return vm.ToValue(ctxObj), nil
}

// marshalResult serializes run()'s return value under the result ceiling.
func marshalResult(rt *goja.Runtime, v goja.Value, maxBytes int) (json.RawMessage, error) {
	if rt == nil || v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil, nil
	}
	// Export walks own enumerable properties and invokes their accessors, so a returned
	// object with a throwing or looping getter runs script code here. Inside Try, that
	// surfaces as a reportable error instead of taking the process down.
	var exported any
	if ex := rt.Try(func() { exported = v.Export() }); ex != nil {
		return nil, fmt.Errorf("the value returned from run() could not be read: %s", trunc(ex.Error(), 512))
	}
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
