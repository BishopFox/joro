package jsautomation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/jsruntime"
)

// maxRuns is how many runs are retained. Each keeps its source verbatim, bounded by
// jsruntime.MaxSourceBytes, so the worst case is a few megabytes against a proxy that
// already holds thousands of captured requests with their bodies. Real scripts are
// kilobytes.
const maxRuns = 50

// Run is the record of one script execution.
//
// Source is retained in full, not just hashed. A hash answers "did this change?", which
// is the right question for an installed automation with an artifact to compare against
// — but a one-shot script submitted over MCP has no artifact, so a hash would leave the
// operator with a fingerprint of code nobody kept. On a tool that sends traffic to a
// client's systems, being able to read exactly what an agent ran is the point.
type Run struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"startedAt"`
	DurationMs int64     `json:"durationMs"`

	// TokenID and TokenName identify the launching token, not the run's synthetic
	// principal: the operator wants to know which credential set this off. Both are
	// empty for a run a trigger started, where TokenName carries the automation name.
	TokenID   string `json:"tokenId"`
	TokenName string `json:"tokenName"`

	// AutomationID is set when this run came from an installed automation, which is
	// also what gave it a storage namespace.
	AutomationID string `json:"automationId,omitempty"`

	Trigger string `json:"trigger"`
	Bundle  string `json:"bundle"`

	Source     string `json:"source"`
	SourceHash string `json:"sourceHash"`

	Result jsruntime.Result `json:"result"`
}

// Summary is the one-line description of a run, used as the audit entry's change text
// and as the header of the tool result.
func (r *Run) Summary() string {
	res := r.Result
	sends := ""
	if res.SendCalls > 0 {
		sends = fmt.Sprintf(" (%d sending)", res.SendCalls)
	}
	return fmt.Sprintf("%s: %s, %d SDK call%s%s, %d ms",
		r.ID, res.Reason, res.Calls, plural(res.Calls), sends, r.DurationMs)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// HashSource returns the hex SHA-256 of a script, which identifies exact code across
// runs and revisions.
func HashSource(src string) string {
	sum := sha256.Sum256([]byte(src))
	return hex.EncodeToString(sum[:])
}

// RunLog is a bounded, in-memory, newest-first record of script runs.
//
// In-memory and process-lifetime, like the capability Activity log it sits beside, and
// for the same reason: an unsigned local record proves nothing to a third party, so it
// is an operator's working view rather than evidence.
type RunLog struct {
	mu   sync.RWMutex
	runs []*Run
	max  int
}

// NewRunLog returns a log retaining at most max runs; max <= 0 uses the default.
func NewRunLog(max int) *RunLog {
	if max <= 0 {
		max = maxRuns
	}
	return &RunLog{max: max}
}

// Add records a run, evicting the oldest once full.
func (l *RunLog) Add(r *Run) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.runs = append(l.runs, r)
	if len(l.runs) > l.max {
		l.runs = l.runs[len(l.runs)-l.max:]
	}
}

// List returns runs newest-first, plus the total held. Sources are omitted: a list of
// fifty scripts is not something to hand a caller by default, and Get exists for the
// one they want to read.
func (l *RunLog) List(offset, limit int) ([]Run, int) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	total := len(l.runs)
	if offset < 0 {
		offset = 0
	}
	out := make([]Run, 0, min(limit, total))
	for i := total - 1 - offset; i >= 0; i-- {
		if limit > 0 && len(out) >= limit {
			break
		}
		r := *l.runs[i]
		r.Source = ""
		out = append(out, r)
	}
	return out, total
}

// Get returns one run, source included.
func (l *RunLog) Get(id string) (Run, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, r := range l.runs {
		if r.ID == id {
			return *r, true
		}
	}
	return Run{}, false
}

// Clear drops every retained run and reports how many went.
func (l *RunLog) Clear() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.runs)
	l.runs = nil
	return n
}

// Count reports how many runs are retained.
func (l *RunLog) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.runs)
}
