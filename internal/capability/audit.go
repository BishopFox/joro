package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DefaultAuditSize is the audit ring's capacity. At roughly 300 bytes an entry
// that is under a megabyte, negligible beside the 5,000-request capture store.
const DefaultAuditSize = 2000

// AuditEntry records one invocation attempt, including the ones that never
// reached a handler. Denials are the entries that matter most: an agent probing
// for capabilities it was not granted shows up here and nowhere else.
type AuditEntry struct {
	Seq int       `json:"seq"`
	At  time.Time `json:"at"`

	TokenID string `json:"tokenId"`
	// TokenName is snapshotted rather than looked up, so a revoked token's
	// history still reads after the token row is gone.
	TokenName string `json:"tokenName"`

	// RunID groups every call a single sandboxed script made. Empty for a direct
	// client call. It is what lets Activity render a run as one collapsible thing
	// instead of a burst of invocations that look unrelated.
	RunID string `json:"runId,omitempty"`

	Capability string `json:"capability"`
	Result     string `json:"result"` // ok | denied | error
	Code       string `json:"code,omitempty"`

	TargetHost   string `json:"targetHost,omitempty"`
	TargetMethod string `json:"targetMethod,omitempty"`
	TargetPath   string `json:"targetPath,omitempty"`
	// HostHeader is recorded only when it differs from the dial target. Blocking
	// the mismatch would break virtual-host testing, which is a real workflow, so
	// it is evidence rather than a rule.
	HostHeader string `json:"hostHeader,omitempty"`

	// RequireScope records that a scope-opted-out token made this call, so an
	// after-the-fact review can find every send that bypassed the scope check.
	RequireScope bool `json:"requireScope"`

	// Credentials records that this call could return unmasked Authorization and
	// Cookie values, so a review can find every one that did.
	Credentials bool `json:"credentials,omitempty"`

	// Privileged records an execution or C2 invocation.
	Privileged bool `json:"privileged,omitempty"`

	// ArgsDigest identifies repeated calls without storing the arguments.
	// Arguments to a send carry credentials, session cookies and payloads;
	// retaining them would make the audit log a secondary secret store that
	// outlives the request it describes. The digest still answers "the agent did
	// this same thing forty times".
	ArgsDigest string `json:"argsDigest,omitempty"`
	ArgsBytes  int    `json:"argsBytes"`

	// Change is a mutating handler's own description of what it altered, via
	// RecordChange. It is the one place arguments are recorded in readable form, and
	// the exception is deliberate: the digest above exists because send arguments
	// carry credentials and payloads, but a scope rule or a Match & Replace pattern
	// is configuration, not a secret — and without this an operator reviewing
	// Activity can see that an agent edited their proxy but not what it did.
	Change string `json:"change,omitempty"`

	OutputBytes int    `json:"outputBytes"`
	DurationMs  int64  `json:"durationMs"`
	ErrMsg      string `json:"errMsg,omitempty"`
}

// Results an AuditEntry can carry.
const (
	ResultOK      = "ok"
	ResultDenied  = "denied"
	ResultError   = "error"
	maxAuditError = 256
	// maxAuditChange bounds one entry's change description. A handler that edits in
	// bulk should summarize rather than enumerate.
	maxAuditChange = 512
)

// changeSink collects a handler's RecordChange calls. Guarded by a mutex because a
// handler may describe its work from a goroutine it spawned.
type changeSink struct {
	mu    sync.Mutex
	parts []string
}

func (s *changeSink) add(msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parts = append(s.parts, msg)
}

func (s *changeSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := strings.Join(s.parts, "; ")
	if len(out) > maxAuditChange {
		out = out[:maxAuditChange] + "…"
	}
	return out
}

type changeSinkKey struct{}

func withChangeSink(ctx context.Context, s *changeSink) context.Context {
	return context.WithValue(ctx, changeSinkKey{}, s)
}

// RecordChange lets a mutating handler describe its own effect for the audit log,
// e.g. RecordChange(ctx, "add include %s", pattern).
//
// It is a no-op when the context carries no sink, so a handler can call it
// unconditionally and a caller outside Invoke does not have to care. Handlers should
// record the effect, not the intent: call it after the mutation succeeds.
func RecordChange(ctx context.Context, format string, args ...any) {
	s, ok := ctx.Value(changeSinkKey{}).(*changeSink)
	if !ok || s == nil {
		return
	}
	s.add(fmt.Sprintf(format, args...))
}

// AuditFilter narrows a listing. Empty fields do not filter.
type AuditFilter struct {
	TokenID    string
	Capability string
	Result     string
	Offset     int
	Limit      int
}

// AuditLog is an in-memory ring buffer, shaped like proxy.Store.
//
// It is deliberately not persisted. A growing on-disk record of engagement
// activity in ~/.joro that nothing prunes is a liability rather than a feature,
// and persisting it would be inconsistent with the capture store and the notes DB,
// both of which die with the process. The UI calls this "Activity" for the same
// reason: an in-memory, unsigned, process-lifetime log proves nothing to a third
// party, and labelling it an audit log would overclaim.
type AuditLog struct {
	mu      sync.RWMutex
	entries []AuditEntry
	maxSize int
	nextSeq int
}

func NewAuditLog(maxSize int) *AuditLog {
	if maxSize <= 0 {
		maxSize = DefaultAuditSize
	}
	return &AuditLog{maxSize: maxSize}
}

// Add appends an entry, assigning its sequence number and evicting the oldest.
func (a *AuditLog) Add(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextSeq++
	e.Seq = a.nextSeq
	if len(e.ErrMsg) > maxAuditError {
		e.ErrMsg = e.ErrMsg[:maxAuditError] + "…"
	}
	a.entries = append(a.entries, e)
	if len(a.entries) > a.maxSize {
		a.entries = a.entries[len(a.entries)-a.maxSize:]
	}
}

// List returns matching entries newest-first, plus the total match count.
func (a *AuditLog) List(f AuditFilter) ([]AuditEntry, int) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	matched := make([]AuditEntry, 0, len(a.entries))
	for i := len(a.entries) - 1; i >= 0; i-- {
		e := a.entries[i]
		if f.TokenID != "" && e.TokenID != f.TokenID {
			continue
		}
		if f.Capability != "" && e.Capability != f.Capability {
			continue
		}
		if f.Result != "" && e.Result != f.Result {
			continue
		}
		matched = append(matched, e)
	}

	total := len(matched)
	if f.Offset > 0 {
		if f.Offset >= total {
			return []AuditEntry{}, total
		}
		matched = matched[f.Offset:]
	}
	if f.Limit > 0 && f.Limit < len(matched) {
		matched = matched[:f.Limit]
	}
	return matched, total
}

// Stats summarizes recent activity for the dashboard widget, which needs counts
// rather than rows. since bounds the window; zero means all retained entries.
func (a *AuditLog) Stats(since time.Time) (total, denied, errors int) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, e := range a.entries {
		if !since.IsZero() && e.At.Before(since) {
			continue
		}
		total++
		switch e.Result {
		case ResultDenied:
			denied++
		case ResultError:
			errors++
		}
	}
	return total, denied, errors
}

// Clear drops every entry. The sequence counter keeps rising, so a cleared log
// cannot make two different invocations share a Seq.
func (a *AuditLog) Clear() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.entries)
	a.entries = nil
	return n
}

// digestArgs fingerprints an argument blob for the audit log without retaining it.
func digestArgs(args json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	sum := sha256.Sum256(args)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func truncErr(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}
