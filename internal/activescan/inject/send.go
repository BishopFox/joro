package inject

import (
	"context"
	"time"

	"github.com/BishopFox/joro/internal/httptools"
)

// maxRespBytes is the response body an injection detector needs — enough to match
// an error string, a rendered expression, or file contents.
const maxRespBytes = 1 << 20

// Sender sends mutated requests through Joro's proxy and fingerprints the result.
// It takes httptools.SendDeps directly (not activescan.RuleDeps) so this package
// does not import activescan — the rules build SendDeps from their RuleDeps.
type Sender struct {
	deps    httptools.SendDeps
	scheme  string
	host    string
	timeout time.Duration
}

// NewSender wires a sender for one target host.
func NewSender(deps httptools.SendDeps, scheme, host string, timeout time.Duration) *Sender {
	if deps.MaxRespBytes == 0 {
		deps.MaxRespBytes = maxRespBytes
	}
	return &Sender{deps: deps, scheme: scheme, host: host, timeout: timeout}
}

// Result is one send's outcome: the raw and parsed response, status, wall-clock
// duration, and a structural fingerprint for differential comparison.
type Result struct {
	RawReq      []byte
	RespRaw     []byte
	Resp        httptools.Response
	Status      int
	DurationMs  int64
	Fingerprint httptools.Fingerprint
	URL         string
	Method      string
}

// Send sends one raw request and returns the fingerprinted result.
func (s *Sender) Send(ctx context.Context, raw []byte) (*Result, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	sent, err := httptools.SendViaProxy(reqCtx, raw, s.scheme, s.host, s.deps)
	if err != nil {
		return nil, err
	}
	return &Result{
		RawReq:      raw,
		RespRaw:     sent.RespRaw,
		Resp:        httptools.ReadResponse(sent.RespRaw),
		Status:      sent.StatusCode,
		DurationMs:  sent.Duration.Milliseconds(),
		Fingerprint: httptools.FingerprintResponse(sent.Seq, sent.RespRaw, sent.Duration.Milliseconds(), false),
		URL:         sent.URL,
		Method:      sent.Method,
	}, nil
}

// Baseline is the unmodified request's response plus a timing floor used to judge
// time-based injections.
type Baseline struct {
	Result
	// FloorMs is the smaller of two baseline round-trips — a jitter-resistant
	// estimate of the endpoint's normal latency.
	FloorMs int64
}

// Baseline sends the original request twice and records the structural fingerprint
// plus the latency floor.
func (s *Sender) Baseline(ctx context.Context, raw []byte) (*Baseline, error) {
	r1, err := s.Send(ctx, raw)
	if err != nil {
		return nil, err
	}
	floor := r1.DurationMs
	if r2, err := s.Send(ctx, raw); err == nil && r2.DurationMs < floor {
		floor = r2.DurationMs
	}
	return &Baseline{Result: *r1, FloorMs: floor}, nil
}

// SameStructure reports whether two responses are the same page ignoring volatile
// content (nonces, timestamps) — the boolean oracle for boolean-based SQLi.
func SameStructure(a, b httptools.Fingerprint) bool { return a.StructHash == b.StructHash }

// LooksDelayed reports whether elapsed indicates an injected delay of at least
// delayMs relative to the baseline floor. The 0.8 factor tolerates the payload
// running slightly short while rejecting ordinary jitter.
func LooksDelayed(elapsedMs, floorMs, delayMs int64) bool {
	return elapsedMs-floorMs >= delayMs*8/10
}
