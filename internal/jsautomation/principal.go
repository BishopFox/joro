package jsautomation

import (
	"crypto/rand"
	"encoding/hex"
	"slices"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/jsruntime"
)

// BundleVersion names the SDK authority contract. A script declares which contract it
// expects; Joro binds that to a fixed grant set. Adding a method to the SDK follows
// ordinary compatibility rules, but a materially more dangerous class of authority
// requires a new version rather than appearing inside this one.
const BundleVersion = "automation-v1"

// runRateLimitPerMin is the run principal's token-bucket rate. Set high on purpose:
// the per-run SDK budget is the containment layer inside a run, and a low rate here
// would turn a budget breach into a slow budget breach while reporting it as
// congestion. Defined locally rather than borrowed from the token store's ceiling,
// which this package has no reason to import.
const runRateLimitPerMin = 600

// BundleGrants returns the capability IDs a run is authorized with.
//
// It is derived from the SDK binding table, not maintained separately, so the JavaScript
// surface and the grant set cannot disagree — a method that exists is granted, and a
// grant that exists is callable.
func BundleGrants() []string { return jsruntime.CapabilityIDs() }

// newRunID returns a run identifier. It doubles as the run's synthetic token ID, so it
// has to be unguessable enough that two runs never collide in the rate limiter or the
// cookie jar.
func newRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice, and a run that cannot be named
		// cannot be isolated, so there is no safe degraded mode here.
		panic("jsautomation: reading random bytes: " + err.Error())
	}
	return "run_" + hex.EncodeToString(b[:])
}

// tokenLaunched reports whether a real automation token started this run.
//
// Derived from TokenID rather than carried as a flag on RunRequest, because the two
// token paths — script.run and script.invoke — receive their principal from
// Registry.Invoke, which always sets it. So this cannot be forgotten the way a bool can,
// and a token path added later gets it for free. The hand-built callers (the operator's
// own UI request, a trigger firing, a lens) have no token and no TokenID.
//
// A run's own synthetic principal, whose TokenID is "run_<hex>", can never arrive here as
// a caller: script.* is excluded from the SDK bundle, and capreg.validateBundle panics at
// startup if that ever stops being true.
func tokenLaunched(caller capability.Principal) bool { return caller.TokenID != "" }

// runPrincipal builds the principal a run's capability calls are made under.
//
// This is where the whole authorization story lives, and it has two halves that behave
// differently on purpose.
//
// Grants come from the bundle and are never intersected with the caller's. That is the
// point of the feature: a token holding script.run may run code that reads history and
// resends requests without also holding history.list and http.resend, because the
// operator authorized a standard automation surface rather than a list of checkboxes.
//
// Policy is inherited, never synthesized. A run launched by a token inherits that token's
// policy verbatim; a run nothing launched inherits the operator's own configuration, which
// is what scopeConfigured carries. Grants say what the code may do; policy says where it
// may reach — and pinning a policy value is not narrowing it. A pinned RequireScope would
// enforce scope on a token the operator deliberately issued unrestricted, then answer with
// a scope_disabled message naming the one remedy they had already applied. Inheritance
// closes the hazard a pin is reached for anyway: a token leashed to one staging host
// leashes its runs, through HostAllow and through its own RequireScope.
//
// Note what a false RequireScope does not mean. Automation sends go through Joro's own
// proxy, so the live scope configuration still filters capture and MITM exactly as it does
// for the operator's browser. Clearing it stops scope being an authorization control; it
// does not turn scope off.
//
// AllowCredentials has no counterpart in the operator's configuration, so a run with no
// token has nothing to inherit and stays masked. Defaulting it on would not be inheriting
// an operator setting, it would be inventing a permissive one for the paths that run
// unattended.
//
// The identity is synthetic, and that is what makes nested calls work. Every per-caller
// limit in the registry — the token bucket, the concurrency counter, the cookie jar —
// is keyed on TokenID. Reusing the caller's would charge a script's fifty reads against
// the operator's own minute budget, and would return "busy" on every single SDK call
// for a token limited to one concurrent request, which is the minimum the UI offers.
// A per-run identity gives the run its own bucket, its own slot, and its own session,
// all of which are torn down when it ends.
//
// noSend drops every capability in sendCaps from the grant set, so the run cannot put
// bytes on the wire. It is a grant restriction rather than a budget because Limits
// cannot express it: Normalize reads a non-positive MaxSendCalls as "take the default".
func runPrincipal(caller capability.Principal, runID string, sendCaps []string, noSend, scopeConfigured bool) capability.Principal {
	grants := make(map[string]struct{}, len(BundleGrants()))
	for _, id := range BundleGrants() {
		if noSend && slices.Contains(sendCaps, id) {
			continue
		}
		grants[id] = struct{}{}
	}

	requireScope, allowCreds := caller.RequireScope, caller.AllowCredentials
	if !tokenLaunched(caller) {
		// No token to inherit from, so the operator's own configuration is the policy.
		// Written out rather than left to the caller's zero value, so the reason sits at
		// the point of decision and a caller that later sets these cannot widen a run.
		requireScope = scopeConfigured
		allowCreds = false
	}

	return capability.Principal{
		TokenID:   runID,
		TokenName: caller.TokenName,
		RunID:     runID,

		Grants: grants,

		RequireScope: requireScope,
		// Inherited in both branches. For a token that is the operator's leash on it; for
		// a run nothing launched it is the automation's own whitelist, which Manager.Invoke
		// substitutes in — operator-owned, edited in the UI, and with RequireScope possibly
		// false it is the narrowing control for anyone who wants one.
		HostAllow:        slices.Clone(caller.HostAllow),
		AllowCredentials: allowCreds,

		// The run budget is the real throttle inside a run: a rate limit here would
		// only convert a budget breach into a slower budget breach, while making the
		// failure look like congestion. The launching token's own rate limit still
		// applies to starting the run.
		RateLimitPerMin: runRateLimitPerMin,
		// Every SDK call is synchronous inside the VM and the worker protocol is
		// strict request/response, so one is not a restriction, it is the shape.
		MaxConcurrent:  1,
		MaxOutputBytes: caller.MaxOutputBytes,
	}
}
