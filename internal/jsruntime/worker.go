package jsruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime/debug"
	"sync"
	"time"
)

// The worker boundary.
//
// A run executes in a second process — a re-exec of the host binary in worker mode —
// and the two halves speak JSON over its stdin and stdout. That buys three things a
// single process cannot:
//
//   - Termination is a kill, not a request. goja's Interrupt is reliable for
//     computation but it is still cooperation; a signal to a process is not.
//   - A memory blowup costs the worker. goja has no allocation ceiling, so the only
//     honest answer to "what if the script allocates 8 GB" is that something dies —
//     and Joro holds captured traffic in memory, so it must not be Joro.
//   - The JSON-only data boundary stops being a rule someone has to keep and becomes
//     a property of the transport. A Go pointer cannot be written to a pipe.
//
// The cost is a process spawn per run, tens of milliseconds against a run measured in
// seconds. Event-driven triggers will want a warm pool; a one-shot script does not.

const (
	// workerGrace is how long after the run's own deadline the parent waits before
	// killing. The child interrupts itself at the deadline so the operator gets logs
	// and a real termination reason; this is the backstop for a child that cannot.
	workerGrace = 5 * time.Second

	// workerWaitDelay bounds cleanup after the context is done: a child ignoring a
	// closed stdin is killed and its pipes closed rather than blocking Wait.
	workerWaitDelay = 2 * time.Second

	// maxWorkerStderr bounds what is kept from the child's stderr. It should be
	// empty; anything there is a Go panic trace, which is worth reporting and worth
	// bounding.
	maxWorkerStderr = 8 << 10

	// maxWireBytes bounds a single protocol frame in either direction. Above the
	// largest capability output plus envelope overhead, and far below anything that
	// would make the parent's buffering interesting.
	maxWireBytes = 64 << 20
)

// frame is one message in either direction. Exactly one field is set.
type frame struct {
	Job   *Request    `json:"job,omitempty"`
	Call  *callFrame  `json:"call,omitempty"`
	Reply *replyFrame `json:"reply,omitempty"`
	Done  *Result     `json:"done,omitempty"`
	// Fatal reports that the worker could not run at all. Distinct from a Result
	// with a failure reason, which means the run happened and did not work.
	Fatal string `json:"fatal,omitempty"`
}

type callFrame struct {
	ID   int             `json:"id"`
	Cap  string          `json:"cap"`
	Args json.RawMessage `json:"args"`
}

type replyFrame struct {
	ID     int             `json:"id"`
	Data   json.RawMessage `json:"data,omitempty"`
	Failed bool            `json:"failed,omitempty"`
	Code   string          `json:"code,omitempty"`
	Msg    string          `json:"msg,omitempty"`
	Denied bool            `json:"denied,omitempty"`
}

// WorkerRuntime runs each program in a fresh child process.
type WorkerRuntime struct {
	exePath string
	args    []string

	// Env is the child's environment. Nil inherits the parent's, which is the
	// default because the Go runtime reads a few variables and an empty environment
	// is not portable. It changes nothing about the sandbox either way: the script
	// has no way to read the process environment, since the global object holds no
	// accessor for one.
	Env []string
}

// NewWorkerRuntime returns a Runtime that spawns exePath with the given arguments.
// The caller supplies the argument that selects worker mode, so this package needs to
// know nothing about the host's command line.
func NewWorkerRuntime(exePath string, args ...string) *WorkerRuntime {
	return &WorkerRuntime{exePath: exePath, args: args}
}

// Run spawns a worker, forwards its capability calls to bridge, and returns its
// result.
//
// The returned error means the worker could not be run or stopped talking mid-run.
// Everything the script did comes back in the Result, including when it was killed:
// a run terminated for memory still reports the calls it made and the logs it wrote,
// because those are what explain it.
func (w *WorkerRuntime) Run(ctx context.Context, req Request, bridge HostBridge) (Result, error) {
	if w.exePath == "" {
		return Result{}, errors.New("no worker executable path configured")
	}
	lim := req.Limits.Normalize()
	req.Limits = lim
	start := time.Now()

	// The parent's deadline is the authoritative one, and deliberately later than the
	// child's own: the child should report a timeout before it is killed for one.
	runCtx, cancel := context.WithTimeout(ctx, lim.Timeout+workerGrace)
	defer cancel()

	cmd := exec.CommandContext(runCtx, w.exePath, w.args...)
	cmd.WaitDelay = workerWaitDelay
	cmd.Env = w.Env

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, fmt.Errorf("worker stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("worker stdout: %w", err)
	}
	var errBuf lockedBuffer
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("starting the script worker: %w", err)
	}

	// The child is killed by runCtx, so Wait always returns; the deferred call is
	// what reaps it if we return early on a protocol failure. Every path calls this,
	// most of them twice, so the outcome is memoized rather than sent on a channel —
	// a second receive on a drained channel would block forever.
	var (
		waitOnce sync.Once
		waitRes  error
	)
	wait := func() error {
		waitOnce.Do(func() { waitRes = cmd.Wait() })
		return waitRes
	}
	defer func() { _ = wait() }()

	enc := json.NewEncoder(stdin)
	dec := json.NewDecoder(io.LimitReader(stdout, maxWireBytes))

	// The job travels on stdin, never in argv: a script may legitimately carry a
	// session token or a payload, and argv is readable by any process on the host.
	if err := enc.Encode(frame{Job: &req}); err != nil {
		return Result{}, fmt.Errorf("sending the job to the worker: %w", err)
	}

	sendCaps := make(map[string]struct{}, len(req.SendCaps))
	for _, id := range req.SendCaps {
		sendCaps[id] = struct{}{}
	}
	// A parent-side backstop on the child's own budget. The child is our binary and
	// enforces this itself; counting here too means a worker that is somehow wrong
	// about its budget still cannot turn one invocation into unbounded work.
	forwarded, forwardedSends := 0, 0

	for {
		var f frame
		if err := dec.Decode(&f); err != nil {
			// End of stream without a result. Distinguish being stopped from the
			// worker simply vanishing, which is what an out-of-memory kill is.
			_ = wait()
			res := Result{
				Calls: forwarded, SendCalls: forwardedSends,
				DurationMs: time.Since(start).Milliseconds(),
			}
			switch {
			case ctx.Err() != nil:
				res.Reason = ReasonCancelled
				res.Err = "the run was cancelled"
			case runCtx.Err() != nil:
				res.Reason = ReasonTimeout
				res.Err = fmt.Sprintf("the run exceeded its %s limit and the worker was stopped", lim.Timeout)
			default:
				res.Reason = ReasonWorkerLost
				res.Err = workerLostDetail(errBuf.String())
			}
			return res, nil
		}

		switch {
		case f.Done != nil:
			res := *f.Done
			res.DurationMs = time.Since(start).Milliseconds()
			_ = wait()
			return res, nil

		case f.Fatal != "":
			_ = wait()
			return Result{
				Reason:     ReasonRuntimeFailure,
				Err:        f.Fatal,
				DurationMs: time.Since(start).Milliseconds(),
			}, nil

		case f.Call != nil:
			rep := replyFrame{ID: f.Call.ID}
			_, isSend := sendCaps[f.Call.Cap]

			switch {
			case forwarded >= lim.MaxCalls,
				isSend && forwardedSends >= lim.MaxSendCalls:
				rep.Failed = true
				rep.Code = "budget_exceeded"
				rep.Msg = "this run has no SDK call budget left"
			default:
				forwarded++
				if isSend {
					forwardedSends++
				}
				data, ierr := bridge.Invoke(runCtx, f.Call.Cap, f.Call.Args)
				if ierr != nil {
					rep.Failed = true
					var ce *CallError
					if errors.As(ierr, &ce) {
						rep.Code, rep.Msg, rep.Denied = ce.Code, ce.Msg, ce.Denied
					} else {
						rep.Code, rep.Msg = "handler_error", ierr.Error()
					}
				} else {
					rep.Data = data
				}
			}

			if err := enc.Encode(frame{Reply: &rep}); err != nil {
				// The child is gone or its stdin is closed; the next Decode will
				// report the stream end with the right reason.
				continue
			}

		default:
			_ = wait()
			return Result{}, errors.New("script worker sent an empty frame")
		}
	}
}

func workerLostDetail(stderr string) string {
	base := "the script worker exited without reporting a result. The usual cause is the " +
		"operating system reclaiming it for memory, which is the containment working"
	if s := bytes.TrimSpace([]byte(stderr)); len(s) > 0 {
		return base + "\nworker stderr: " + trunc(string(s), maxWorkerStderr)
	}
	return base
}

// lockedBuffer collects the child's stderr. exec writes to it from its own goroutine
// while the parent may read it after Wait, so the lock is not decorative.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() >= maxWorkerStderr {
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// RunWorker is the child half. It reads one job from in, runs it, and writes the
// result to out. Every capability call is forwarded to the parent and waited on, which
// is what makes the whole protocol strict request/response: the SDK is synchronous
// inside the VM, so two calls can never be in flight at once.
//
// The host's main should call this and exit. It never returns a Result — the result
// goes on the wire — only an error that could not be reported that way.
func RunWorker(ctx context.Context, in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(io.LimitReader(in, maxWireBytes))
	enc := json.NewEncoder(out)

	var f frame
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("reading the job: %w", err)
	}
	if f.Job == nil {
		return errors.New("first frame was not a job")
	}
	job := *f.Job
	job.Limits = job.Limits.Normalize()

	// Go's soft heap limit makes the collector work harder as the script approaches
	// the ceiling, which slows a runaway allocation enough for the VM's own sampling
	// watchdog to catch it. It does not fail allocations, so it is a delay rather
	// than a wall — the wall is this process being expendable.
	prev := debug.SetMemoryLimit(job.Limits.MemoryBytes + workerHeadroom)
	defer debug.SetMemoryLimit(prev)

	bridge := &pipeBridge{enc: enc, dec: dec}
	res, err := New().Run(ctx, job, bridge)
	if err != nil {
		// A runtime failure that produced no Result at all.
		return enc.Encode(frame{Fatal: err.Error()})
	}
	if bridge.broken != nil {
		// The parent stopped answering. It already knows; writing a result into a
		// dead pipe is pointless, and reporting the pipe error here is honest.
		return bridge.broken
	}
	return enc.Encode(frame{Done: &res})
}

// workerHeadroom is what the worker needs on top of the script's own ceiling for the
// Go runtime, goja's compiled program, and the frame being marshalled.
const workerHeadroom int64 = 48 << 20

// pipeBridge forwards capability calls to the parent process.
type pipeBridge struct {
	enc    *json.Encoder
	dec    *json.Decoder
	nextID int
	broken error
}

func (b *pipeBridge) Invoke(_ context.Context, id string, args json.RawMessage) (json.RawMessage, error) {
	if b.broken != nil {
		return nil, &CallError{Code: "handler_error", Msg: "the host is no longer reachable"}
	}
	b.nextID++
	callID := b.nextID

	if err := b.enc.Encode(frame{Call: &callFrame{ID: callID, Cap: id, Args: args}}); err != nil {
		b.broken = fmt.Errorf("sending a capability call: %w", err)
		return nil, &CallError{Code: "handler_error", Msg: "the host is no longer reachable"}
	}

	var f frame
	if err := b.dec.Decode(&f); err != nil {
		b.broken = fmt.Errorf("reading a capability reply: %w", err)
		return nil, &CallError{Code: "handler_error", Msg: "the host is no longer reachable"}
	}
	if f.Reply == nil || f.Reply.ID != callID {
		b.broken = errors.New("host replied out of sequence")
		return nil, &CallError{Code: "handler_error", Msg: "the host replied out of sequence"}
	}
	if f.Reply.Failed {
		return nil, &CallError{Code: f.Reply.Code, Msg: f.Reply.Msg, Denied: f.Reply.Denied}
	}
	return f.Reply.Data, nil
}
