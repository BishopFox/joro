// Package activescan is Joro's operator-initiated active scanning: unlike detect,
// echo and anomaly — which only ever read captured traffic — a scan originates
// traffic or drives a browser against a target the operator picked, and files
// confirmed results into the shared detect.Store.
//
// # A framework, not one check
//
// A scan runs a set of pluggable Rules against one Target. DOM XSS is the first
// and only rule today; the interface exists so a future active rule (a reflected-
// XSS prober, an open-redirect check) plugs in without the run machinery, the
// scope rule or the context-menu wiring changing. The registry is an instance a
// caller builds and owns, not a package global, per the project's no-globals rule.
//
// # One run at a time
//
// Like internal/chainrun, a scan is sequential and the store refuses a second
// concurrent run (the AddIfIdle guard). A DOM XSS scan drives a single browser
// and a future state-changing rule would race the application's own state, so
// coexisting runs would describe the interleaving rather than the target.
//
// # Scope is a filter, not a gate
//
// The target's URLs are scope-filtered by the handler through proxy.Scope.InScope,
// which returns true whenever scope filtering is disabled. So with scope off — the
// default — nothing is rejected and a scan covers every target; scope only narrows
// a scan once the operator turns it on. Rules therefore receive an already-filtered
// URL list and never re-check.
package activescan

import (
	"context"
	"sort"
	"sync"

	"github.com/BishopFox/joro/internal/callback"
	"github.com/BishopFox/joro/internal/cert"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/techfp"
)

// Status is a run's state.
type Status string

const (
	StatusRunning  Status = "running"
	StatusComplete Status = "complete"
	StatusStopped  Status = "stopped"
)

// Bounds.
const (
	MaxRuns = 20

	// MaxURLs caps a single host scan: a large site map should not turn one click
	// into thousands of navigations.
	MaxURLs = 200

	DefaultBudgetMs = 600000  // 10 minutes
	MaxBudgetMs     = 1800000 // 30 minutes
)

// TargetURL is one address to exercise.
type TargetURL struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	RequestID string `json:"requestId,omitempty"` // the capture it came from, if any
	// RawReq carries the captured request bytes for a future HTTP-sending rule.
	// The DOM XSS rule navigates to URL and ignores it.
	RawReq []byte `json:"-"`
}

// Target is what a scan operates on: one host's endpoints, or a single request.
type Target struct {
	Scheme string      `json:"scheme"`
	Host   string      `json:"host"`   // Host-header form (may carry :port)
	Origin string      `json:"origin"` // scheme://host
	URLs   []TargetURL `json:"-"`
}

// Config is snapshotted when a run starts.
type Config struct {
	// Scope records how the target was chosen, for display: "host" or "request".
	Scope string

	// Rules names the rule IDs to run; empty means every registered rule.
	Rules []string

	// AllowDestructive is the arming gate reserved for rules that change state.
	// DOM XSS is read-only navigation and does not consult it, but the field is
	// the seam a future rule's Plan refusal hangs on.
	AllowDestructive bool

	// Tags and Severity narrow which signatures the template rule runs; empty
	// means no filter. IgnoreFingerprint makes that rule skip fingerprint gating
	// and run every eligible signature. Only the template-signature rule reads
	// these; other rules ignore them.
	Tags              []string
	Severity          []string
	IgnoreFingerprint bool

	// NoOAST opts the injection rules out of out-of-band testing even when a
	// callback listener is configured. OAST is already disabled when no listener
	// is configured; this is the operator's explicit opt-out when one is.
	NoOAST bool

	BudgetMs int
}

// RuleDeps is everything a rule might need to originate traffic or drive a
// browser. A rule takes what it uses and ignores the rest.
type RuleDeps struct {
	ProxyAddr string
	CA        *cert.CA
	Store     *proxy.Store
	Scope     *proxy.Scope
	DataDir   string
	// Tech is the passive fingerprint store. The template-signature rule reads it
	// to run only the checks a host's detected stack warrants; nil disables gating
	// (every eligible signature runs).
	Tech *techfp.Store
	// Callback is the out-of-band (OAST) callback store. The injection rules mint a
	// token and poll it for blind interactions; nil (or no configured domain)
	// disables OAST vectors, so they run only when a listener/domain is configured.
	Callback *callback.Store
}

// Reporter is how a rule reports progress and results back to the run. Both
// methods are safe to call from the rule's own goroutines.
type Reporter interface {
	// Finding files a confirmed result into the shared detect store.
	Finding(detect.Finding)
	// Progress advances the run's completed count by delta units of work.
	Progress(delta int)
}

// Rule is one active check. It owns its own traversal and resources: the DOM XSS
// rule launches one browser and drives every URL through it, tearing it down
// when Run returns.
type Rule interface {
	ID() string
	Name() string
	Category() detect.Category
	// Description explains what the rule does, for the Rules UI. It is the active
	// counterpart to a passive rule's Description field.
	Description() string
	Run(ctx context.Context, t Target, cfg Config, deps RuleDeps, rep Reporter) error
}

// Registry holds the rules a host process offers. It is built and owned by the
// caller (the API server), not a package global.
//
// A rule's enabled-state is stored as the DISABLED set (an absent id is enabled),
// so a newly-registered rule defaults on with no migration and the project file
// persists only the exceptions. The enabled-state is per-project session state:
// applyProjectConfig sets it on a project switch and buildProjectConfig reads it.
type Registry struct {
	mu       sync.RWMutex
	rules    map[string]Rule
	order    []string
	disabled map[string]bool
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{rules: make(map[string]Rule), disabled: make(map[string]bool)}
}

// Register adds a rule, keeping registration order for listing.
func (r *Registry) Register(rule Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rules[rule.ID()]; !ok {
		r.order = append(r.order, rule.ID())
	}
	r.rules[rule.ID()] = rule
}

// Get returns a rule by ID, or nil.
func (r *Registry) Get(id string) Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rules[id]
}

// All returns every registered rule in registration order.
func (r *Registry) All() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rule, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.rules[id])
	}
	return out
}

// IsEnabled reports whether a rule runs when no explicit selection is made.
func (r *Registry) IsEnabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.disabled[id]
}

// SetEnabled toggles a rule's enabled-state.
func (r *Registry) SetEnabled(id string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if on {
		delete(r.disabled, id)
	} else {
		r.disabled[id] = true
	}
}

// Disabled returns the disabled rule IDs, sorted — the set the project file
// persists.
func (r *Registry) Disabled() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.disabled))
	for id := range r.disabled {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// SetDisabled replaces the disabled set, for a project restore. A nil slice
// clears it, so a project with no setting runs every rule.
func (r *Registry) SetDisabled(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.disabled = make(map[string]bool, len(ids))
	for _, id := range ids {
		r.disabled[id] = true
	}
}

// Resolve returns the rules a config selects, in registration order. An empty
// selection means every ENABLED rule; an explicit selection returns the named
// registered rules regardless of enabled-state, so an operator choosing a rule
// overrides its global toggle.
func (r *Registry) Resolve(ids []string) []Rule {
	if len(ids) == 0 {
		out := make([]Rule, 0, len(r.order))
		for _, rule := range r.All() {
			if r.IsEnabled(rule.ID()) {
				out = append(out, rule)
			}
		}
		return out
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := make([]Rule, 0, len(ids))
	for _, rule := range r.All() {
		if want[rule.ID()] {
			out = append(out, rule)
		}
	}
	return out
}

func clampInt(v, def, lo, hi int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
