package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// idPattern is the permitted shape of a capability ID: lowercase dotted segments,
// no underscores. The underscore ban is not cosmetic — MCP tool names are derived
// by replacing dots with underscores, and that mapping is only reversible while no
// ID contains one.
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$`)

// Registry holds every capability exposed to automation and is the only path to
// invoking one. Registration happens once at process start, from internal/capreg;
// after that the map is read-only, so Invoke needs no lock on it.
type Registry struct {
	caps map[string]Capability
	ids  []string // sorted, for List and Fingerprint

	scope ScopeChecker
	audit *AuditLog
	rate  *rateLimiter

	sem chan struct{}

	mu     sync.RWMutex
	sealed bool

	// now is swappable for tests; nil means time.Now.
	now func() time.Time
}

// NewRegistry creates an empty registry. scope may be nil, which the guard treats
// as scope-disabled — that is the fail-closed direction for a RequireScope
// principal, so a missing scope engine denies sends rather than allowing them.
func NewRegistry(scope ScopeChecker, audit *AuditLog) *Registry {
	if audit == nil {
		audit = NewAuditLog(DefaultAuditSize)
	}
	return &Registry{
		caps:  make(map[string]Capability),
		scope: scope,
		audit: audit,
		rate:  newRateLimiter(),
		sem:   make(chan struct{}, DefaultGlobalConurrent),
	}
}

func (r *Registry) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Audit exposes the log so the REST layer can list it.
func (r *Registry) Audit() *AuditLog { return r.audit }

// Forget drops per-principal limiter state, called when a token is revoked.
func (r *Registry) Forget(tokenID string) { r.rate.Forget(tokenID) }

// Register validates and adds a capability.
//
// Validation failures that indicate a *policy* violation — a reserved ID, or a
// mutating scope capability — panic rather than return, because a build that
// reaches those lines has a design bug and there is no honest way to continue.
// Everything else returns an error. capreg uses MustRegister throughout, running
// at process start before any listener binds, which is the same posture as
// regexp.MustCompile; no package here calls os.Exit.
func (r *Registry) Register(c Capability) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed {
		return errors.New("capability: registry is sealed; register at startup only")
	}

	// Policy violations panic. These are the checks that make grant administration
	// structurally impossible rather than merely absent.
	if IsReserved(c.ID) {
		panic(fmt.Sprintf(
			"capability: %q is in a reserved namespace. Token issuance, grant editing and MCP "+
				"listener administration are UI-only by design: a token that can mint or widen "+
				"tokens is not a boundary. Reserved prefixes: %s",
			c.ID, strings.Join(reservedPrefixes, " ")))
	}
	if c.Class == ClassScope && c.Mutating {
		panic(fmt.Sprintf(
			"capability: %q is scope-class and mutating. Scope is the safety control the send "+
				"guard depends on; an agent that can widen its own leash has no leash. "+
				"Read-only scope introspection is fine.", c.ID))
	}

	switch {
	case !idPattern.MatchString(c.ID):
		return fmt.Errorf("capability: invalid ID %q (want lowercase dotted segments, no underscores)", c.ID)
	case !validClass(c.Class):
		return fmt.Errorf("capability %s: unknown class %q", c.ID, c.Class)
	case c.Title == "":
		return fmt.Errorf("capability %s: Title is required", c.ID)
	case c.Description == "":
		return fmt.Errorf("capability %s: Description is required (it is the contract text an agent reads)", c.ID)
	case c.Handler == nil:
		return fmt.Errorf("capability %s: Handler is required", c.ID)
	case c.SendsTraffic && c.Target == nil:
		return fmt.Errorf("capability %s: SendsTraffic requires a Target extractor, or the scope guard has nothing to check", c.ID)
	}
	if _, dup := r.caps[c.ID]; dup {
		return fmt.Errorf("capability: duplicate ID %q", c.ID)
	}
	if err := validateSchema(c.ID, c.InputSchema); err != nil {
		return err
	}

	r.caps[c.ID] = c
	r.ids = append(r.ids, c.ID)
	sort.Strings(r.ids)
	return nil
}

// MustRegister panics on any registration failure.
func (r *Registry) MustRegister(c Capability) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Seal closes the registry to further registration. Called once after capreg has
// built it, so a plugin or a later code path cannot slip a capability in behind
// the grant picker's back.
func (r *Registry) Seal() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sealed = true
}

func validateSchema(id string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("capability %s: InputSchema is required", id)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("capability %s: InputSchema is not valid JSON: %w", id, err)
	}
	if t, _ := doc["type"].(string); t != "object" {
		return fmt.Errorf(`capability %s: InputSchema must have "type":"object"`, id)
	}
	return nil
}

// Get returns a capability by ID.
func (r *Registry) Get(id string) (Capability, bool) {
	c, ok := r.caps[id]
	return c, ok
}

// All returns every registered capability, sorted by ID. Used by the grant picker,
// which must show capabilities a principal does not hold.
func (r *Registry) All() []Capability {
	out := make([]Capability, 0, len(r.ids))
	for _, id := range r.ids {
		out = append(out, r.caps[id])
	}
	return out
}

// List returns the capabilities a principal may invoke, sorted by ID. This is what
// backs the MCP filtered tools/list: an ungranted capability is not merely refused
// on call, it is never named.
func (r *Registry) List(p Principal) []Capability {
	out := make([]Capability, 0, len(r.ids))
	for _, id := range r.ids {
		if p.Can(id) {
			out = append(out, r.caps[id])
		}
	}
	return out
}

// IDs returns every registered capability ID, sorted.
func (r *Registry) IDs() []string {
	out := make([]string, len(r.ids))
	copy(out, r.ids)
	return out
}

// Fingerprint hashes the sorted capability ID set. A token records the fingerprint
// current at its last grant review, so the UI can tell an operator that new
// capabilities exist without ever granting one implicitly.
func (r *Registry) Fingerprint() string {
	h := sha256.New()
	for _, id := range r.ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Invoke runs a capability on behalf of a principal, applying every guard.
//
// The order matters and each step fails closed. An audit entry is written from a
// deferred call, so denials, timeouts and recovered panics all land in the log —
// the failures are the entries an operator most needs.
func (r *Registry) Invoke(ctx context.Context, p Principal, id string, args json.RawMessage) (res Result, err error) {
	start := r.clock()
	entry := AuditEntry{
		At:           start,
		TokenID:      p.TokenID,
		TokenName:    p.TokenName,
		Capability:   id,
		RequireScope: p.RequireScope,
		ArgsDigest:   digestArgs(args),
		ArgsBytes:    len(args),
	}
	defer func() {
		entry.DurationMs = r.clock().Sub(start).Milliseconds()
		switch {
		case err == nil:
			entry.Result = ResultOK
			entry.OutputBytes = res.Bytes
		default:
			entry.Code = CodeOf(err)
			entry.ErrMsg = truncErr(err)
			if isDenial(entry.Code) {
				entry.Result = ResultDenied
			} else {
				entry.Result = ResultError
			}
		}
		r.audit.Add(entry)
	}()

	// 1. Authorization, and it swallows existence. An unknown capability and an
	//    ungranted one return the same code and the same message, so tools/call
	//    is never an oracle for what a token was not given.
	capDef, ok := r.caps[id]
	if !ok || !p.Can(id) {
		return Result{}, errf(CodeForbidden, "unknown or not granted: %s", id)
	}

	// 2. Reserved-prefix re-check. Redundant with Register, one string compare, and
	//    the thing that still holds if a grant list is hand-edited.
	if IsReserved(id) {
		return Result{}, errf(CodeForbidden, "unknown or not granted: %s", id)
	}

	// 3. Global concurrency, non-blocking. An agent firing fifty parallel calls
	//    gets a fast busy rather than a queue that starves the operator's own
	//    browsing through the same process.
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		return Result{}, errf(CodeBusy, "Joro is at its global automation concurrency limit; retry shortly")
	}

	// 4. Per-principal concurrency and rate limit.
	if !r.rate.acquire(p.TokenID, p.MaxConcurrent) {
		return Result{}, errf(CodeBusy, "this token is at its concurrency limit; retry shortly")
	}
	defer r.rate.release(p.TokenID)

	if ok, retry := r.rate.allow(p.TokenID, p.RateLimitPerMin, r.clock()); !ok {
		e := errf(CodeRateLimited, "rate limit exceeded for this token; retry in %dms", retry.Milliseconds())
		e.RetryAfterMs = int(retry.Milliseconds())
		return Result{}, e
	}

	// 5. Scope guard, for capabilities that emit traffic. The registry extracts the
	//    target itself, before any handler code runs, so a handler cannot skip the
	//    check and is not trusted to perform it.
	if capDef.SendsTraffic {
		target, terr := capDef.Target(args)
		if terr != nil {
			return Result{}, wrapErr(terr, CodeInvalidArgs)
		}
		entry.TargetHost = normalizeHost(target.Host)
		entry.TargetMethod = target.Method
		entry.TargetPath = target.Path
		if gerr := checkTarget(p, r.scope, target); gerr != nil {
			return Result{}, gerr
		}
	}

	// 6. Execute, bounded and recovered. A handler reachable by a network peer must
	//    not take the proxy down on a nil dereference.
	callCtx, cancel := context.WithTimeout(ctx, capDef.timeout())
	defer cancel()

	data, herr := runRecovered(callCtx, capDef, Input{Args: args, Principal: p})
	if herr != nil {
		if errors.Is(herr, context.DeadlineExceeded) {
			return Result{}, errf(CodeTimeout, "%s timed out after %s", id, capDef.timeout())
		}
		return Result{}, wrapErr(herr, CodeHandlerError)
	}

	// 7. Output cap. Truncated JSON would be mis-parsed silently, so an oversize
	//    result is an honest failure that names the way to narrow it.
	encoded, merr := json.Marshal(data)
	if merr != nil {
		return Result{}, errf(CodeHandlerError, "encoding result: %v", merr)
	}
	if limit := principalOutputCap(p, capDef); len(encoded) > limit {
		return Result{}, errf(CodeOutputTooLarge,
			"result is %d bytes, over the %d byte limit for %s. Narrow the filter, lower limit, or request a smaller range.",
			len(encoded), limit, id)
	}

	return Result{Data: data, Bytes: len(encoded), Duration: r.clock().Sub(start)}, nil
}

// principalOutputCap takes the tighter of the capability's cap and the token's.
func principalOutputCap(p Principal, c Capability) int {
	limit := c.maxOutputBytes()
	if p.MaxOutputBytes > 0 && p.MaxOutputBytes < limit {
		return p.MaxOutputBytes
	}
	return limit
}

func runRecovered(ctx context.Context, c Capability, in Input) (data any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errf(CodePanic, "%s panicked: %v", c.ID, rec)
		}
	}()
	return c.Handler(ctx, in)
}

// wrapErr keeps an *Error's own code and gives anything else the fallback.
func wrapErr(err error, fallback string) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: fallback, Msg: err.Error()}
}

// isDenial separates "the guard said no" from "the work failed", which is the
// distinction the Activity view surfaces: denials are about the token's grants,
// errors are about the target or the arguments.
func isDenial(code string) bool {
	switch code {
	case CodeForbidden, CodeScopeDisabled, CodeScopeEmpty, CodeOutOfScope,
		CodeHostNotAllowed, CodeRateLimited, CodeBusy:
		return true
	}
	return false
}
