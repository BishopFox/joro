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
// Policy narrows and never widens. RequireScope is pinned on and AllowCredentials
// pinned off regardless of what the launching token allows, and HostAllow is inherited
// verbatim. Grants say what the code may do; policy says where it may reach. Without
// this half, an operator who leashed a token to one staging host and then granted
// script.run would have silently handed an agent every host in scope — a widening they
// could not see, against a guard written to fail closed.
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
func runPrincipal(caller capability.Principal, runID string, sendCaps []string, noSend bool) capability.Principal {
	grants := make(map[string]struct{}, len(BundleGrants()))
	for _, id := range BundleGrants() {
		if noSend && slices.Contains(sendCaps, id) {
			continue
		}
		grants[id] = struct{}{}
	}

	return capability.Principal{
		TokenID:   runID,
		TokenName: caller.TokenName,
		RunID:     runID,

		Grants: grants,

		RequireScope:     true,
		HostAllow:        slices.Clone(caller.HostAllow),
		AllowCredentials: false,

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
