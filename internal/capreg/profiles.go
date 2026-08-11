package capreg

import (
	"fmt"
	"slices"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
)

// Profiles are curated grant bundles, so issuing a correctly-shaped token is one
// click rather than thirty checkboxes.
//
// The load-bearing rule: a profile is expanded into a concrete list of capability IDs
// when the token is created, and the profile is never stored on the token as a live
// reference. This is the no-wildcard rule from internal/automation applied one level
// up. A profile that gains a send-capable or mutating capability in a later release
// must not retroactively widen a token issued today; the existing per-token
// "capabilities you have not granted" machinery surfaces the addition instead, and the
// operator decides.
//
// Profiles are declared here, in the same package as the capabilities, so
// validateProfiles can check every ID against the registry at startup. There is no
// operator-defined profile: these are a convenience over the grant picker, not a
// second place where authorization lives.

// Profile is a named grant bundle plus the token settings it expects.
type Profile struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`

	// Grants is the fully expanded capability ID list. No wildcards, ever.
	Grants []string `json:"grants"`

	// RequireScope is the recommended setting for the token, not a constraint the
	// registry enforces. A profile granting an UnrestrictedOnly capability must leave
	// it false or those grants are denied on every call — validateProfiles checks it.
	RequireScope bool `json:"requireScope"`

	// AllowsSends declares that this profile is meant to emit traffic. It exists so
	// validateProfiles can fail the build if a profile picks up a send capability
	// without someone having decided that it should.
	AllowsSends bool `json:"allowsSends"`

	RateLimitPerMin int `json:"rateLimitPerMin"`
	MaxConcurrent   int `json:"maxConcurrent"`
}

// Read-only capability IDs, the base every profile builds on. Listed explicitly
// rather than derived from the !Mutating && !SendsTraffic predicate: the grant picker
// already offers that predicate as its "Read-only" preset, and a profile should be a
// deliberate set that does not silently absorb every future read capability.
var reconGrants = []string{
	"history.list",
	"history.stats",
	"sitemap.get",
	"scope.get",
	"findings.list",
	"findings.get",
	"notes.list",
	"notes.hosts",
	"http.fingerprint",
	"http.read",
	"http.search",
	"http.diff",
	"config.intercept.get",
}

// Profiles returns the built-in profiles, in the order the UI shows them.
func Profiles() []Profile {
	return []Profile{
		{
			ID:    "recon",
			Title: "Recon (read-only)",
			Description: "Read captured traffic, the site map, scope, findings and notes. Sends nothing and " +
				"changes nothing. The right default for an agent that is orienting itself.",
			Grants:          slices.Clone(reconGrants),
			RequireScope:    true,
			RateLimitPerMin: 60,
			MaxConcurrent:   2,
		},
		{
			ID:    "tester",
			Title: "Active tester",
			Description: "Recon, plus resending edited requests and sending capped batches of variants " +
				"through the proxy. Emits real traffic to targets, so it is held to the scope guard.",
			Grants:          append(slices.Clone(reconGrants), "http.resend", "http.batch"),
			RequireScope:    true,
			AllowsSends:     true,
			RateLimitPerMin: 120,
			MaxConcurrent:   4,
		},
		{
			ID:    "triage",
			Title: "Triage analyst",
			Description: "Recon, plus marking false positives, re-grading findings and writing notes. Sends " +
				"nothing. For working through a detection backlog without touching the target.",
			Grants: append(slices.Clone(reconGrants),
				"findings.update", "notes.create", "detect.rules.list", "detect.config.get"),
			RequireScope:    true,
			RateLimitPerMin: 120,
			MaxConcurrent:   2,
		},
		{
			ID:    "setup",
			Title: "Engagement setup",
			Description: "Recon, plus configuring the proxy for an engagement: scope include rules, Match & " +
				"Replace, Custom Data, noise patterns and detection tuning. Sends nothing itself. Requires a " +
				"token with scope enforcement off, since a token restricted by scope cannot edit scope — and " +
				"note that adding a scope rule makes Joro intercept and record that host.",
			Grants: append(slices.Clone(reconGrants),
				"scope.addrule", "scope.enable",
				"config.replace.list", "config.replace.edit",
				"config.customdata.list", "config.customdata.edit",
				"config.noise.list", "config.noise.edit",
				"detect.rules.list", "detect.rules.edit",
				"detect.config.get", "detect.config.set", "detect.rescan",
				"notes.create"),
			RequireScope:    false,
			RateLimitPerMin: 60,
			MaxConcurrent:   2,
		},
		{
			ID:    "operator",
			Title: "Full operator",
			Description: "Every capability Joro exposes: reads, sends, configuration and scope. Scope " +
				"enforcement is off so the scope grants work, which means this token can reach any host. " +
				"Issue it only for an agent you are supervising.",
			Grants:          nil, // filled from the registry by validateProfiles
			RequireScope:    false,
			AllowsSends:     true,
			RateLimitPerMin: 120,
			MaxConcurrent:   4,
		},
	}
}

// operatorProfileID is the one profile whose grants are the whole registry, resolved
// at startup rather than hand-listed so it cannot drift out of date.
const operatorProfileID = "operator"

// builtProfiles is the validated, resolved set. Populated once by validateProfiles
// during capreg.Build, before the registry is sealed.
var builtProfiles []Profile

// validateProfiles resolves and checks every profile, panicking on a problem.
//
// A panic rather than an error because this runs from Build at process start, before
// any listener binds — the same posture as MustRegister and regexp.MustCompile. A
// profile naming a capability that does not exist is a build mistake with no honest
// runtime behavior: silently dropping the ID would hand out a token quietly missing a
// grant the operator believed they had selected.
func validateProfiles(r *capability.Registry) {
	known := make(map[string]capability.Capability, len(r.IDs()))
	for _, c := range r.All() {
		known[c.ID] = c
	}

	profiles := Profiles()
	seen := make(map[string]struct{}, len(profiles))
	for i := range profiles {
		p := &profiles[i]

		if p.ID == "" || p.Title == "" || p.Description == "" {
			panic(fmt.Sprintf("capreg: profile %q needs an ID, Title and Description", p.ID))
		}
		if _, dup := seen[p.ID]; dup {
			panic(fmt.Sprintf("capreg: duplicate profile ID %q", p.ID))
		}
		seen[p.ID] = struct{}{}

		if p.ID == operatorProfileID {
			p.Grants = r.IDs()
		}
		if len(p.Grants) == 0 {
			panic(fmt.Sprintf("capreg: profile %q grants nothing", p.ID))
		}

		slices.Sort(p.Grants)
		p.Grants = slices.Compact(p.Grants)

		for _, id := range p.Grants {
			c, ok := known[id]
			switch {
			case !ok:
				panic(fmt.Sprintf("capreg: profile %q grants %q, which is not registered. "+
					"A renamed or removed capability must be updated here too, or the profile hands "+
					"out a grant the operator thinks they selected and does not have.", p.ID, id))
			case capability.IsReserved(id):
				panic(fmt.Sprintf("capreg: profile %q grants reserved ID %q", p.ID, id))
			case c.SendsTraffic && !p.AllowsSends:
				panic(fmt.Sprintf("capreg: profile %q grants %q, which sends traffic, but does not set "+
					"AllowsSends. Either it should, or the grant does not belong in this profile.", p.ID, id))
			case c.UnrestrictedOnly && p.RequireScope:
				panic(fmt.Sprintf("capreg: profile %q sets RequireScope and grants %q, which is refused to "+
					"any token restricted by scope. That combination mints a token whose grant is denied on "+
					"every call.", p.ID, id))
			}
		}
	}
	builtProfiles = profiles
}

// BuiltProfiles returns the validated profiles for the REST layer. Empty until Build
// has run, which is the same lifecycle the registry itself has.
func BuiltProfiles() []Profile {
	out := make([]Profile, len(builtProfiles))
	copy(out, builtProfiles)
	for i := range out {
		out[i].Grants = slices.Clone(out[i].Grants)
	}
	return out
}

// ProfileSummary renders the profiles as a one-line-each listing, for logs.
func ProfileSummary() string {
	var parts []string
	for _, p := range builtProfiles {
		parts = append(parts, fmt.Sprintf("%s(%d)", p.ID, len(p.Grants)))
	}
	return strings.Join(parts, " ")
}
