package capability

import (
	"sync"
	"time"
)

// Registry-wide limit defaults. Per-principal values override the rate and
// concurrency figures; the global semaphore is not overridable, because its job is
// to protect the operator's own browsing from an agent's fan-out.
const (
	DefaultRateLimitPerMin = 60
	DefaultMaxConcurrent   = 2
	DefaultGlobalConurrent = 8
)

// rateLimiter is a per-principal token bucket, keyed by token ID.
//
// It lives in the registry rather than in the token store because the registry
// owns enforcement while the store owns identity; that split is what lets the
// store be swapped or absent without the guard losing a limit. State is keyed by
// token ID and reclaimed when a token is revoked.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	capacity float64
	perSec   float64
	last     time.Time
	// inFlight is the principal's own concurrency count, tracked here so both
	// limits share one lock and one lifetime.
	inFlight int
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket)}
}

// allow consumes one token for the principal, refilling by elapsed time first.
// It returns the suggested retry delay when the bucket is empty.
//
// Burst capacity equals the per-minute rate, so an agent may open with a short
// fan-out and then settles to the steady rate. That matches how an agent actually
// works — a burst of reads to orient, then paced sends — better than a strict
// interval would.
func (rl *rateLimiter) allow(tokenID string, perMin int, now time.Time) (bool, time.Duration) {
	if perMin <= 0 {
		perMin = DefaultRateLimitPerMin
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[tokenID]
	if !ok {
		b = &bucket{tokens: float64(perMin), capacity: float64(perMin), perSec: float64(perMin) / 60, last: now}
		rl.buckets[tokenID] = b
	}
	// A changed limit takes effect on the next call rather than at next refill,
	// so lowering a token's rate in the UI is immediate.
	if b.capacity != float64(perMin) {
		b.capacity = float64(perMin)
		b.perSec = float64(perMin) / 60
		b.tokens = min(b.tokens, b.capacity)
	}

	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.capacity, b.tokens+elapsed.Seconds()*b.perSec)
		b.last = now
	}
	if b.tokens < 1 {
		need := (1 - b.tokens) / b.perSec
		return false, time.Duration(need * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// acquire takes one of the principal's concurrency slots without blocking.
func (rl *rateLimiter) acquire(tokenID string, maxConcurrent int) bool {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[tokenID]
	if !ok {
		b = &bucket{tokens: 0, capacity: 0, perSec: 0}
		rl.buckets[tokenID] = b
	}
	if b.inFlight >= maxConcurrent {
		return false
	}
	b.inFlight++
	return true
}

func (rl *rateLimiter) release(tokenID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if b, ok := rl.buckets[tokenID]; ok && b.inFlight > 0 {
		b.inFlight--
	}
}

// Forget drops a principal's limiter state. Called when a token is revoked so a
// reissued ID does not inherit a drained bucket.
func (rl *rateLimiter) Forget(tokenID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, tokenID)
}
