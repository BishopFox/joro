package jsautomation

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/jsruntime"
)

// SDKVersion1 binds to the automation-v1 bundle. A manifest declares which SDK
// contract it expects; Joro decides what that contract grants. Adding a method to the
// SDK follows ordinary compatibility rules, but a materially more dangerous class of
// authority takes a new version rather than appearing inside this one.
const SDKVersion1 = "1"

// Trigger names. These are Joro's own event type strings, not a parallel vocabulary —
// an automation subscribes to the thing that already happens.
//
// callback.interaction is deliberately absent. Every callback listener is constructed
// in listener mode, scripting exists only in proxy mode, and the team relay forwards
// nothing but team.* — so a proxy-mode dispatcher would be waiting for an event that
// structurally cannot arrive. Offering it would be a trigger that silently never fires.
const (
	TriggerManual          = "manual"
	TriggerRequestCaptured = "request.captured"
	TriggerDetectFinding   = "detect.finding"
	TriggerFuzzerComplete  = "fuzzer.complete"
)

// Triggers lists every subscribable trigger, in the order the UI shows them: manual
// first, then cheapest-to-reason-about to most consequential.
var Triggers = []string{
	TriggerManual,
	TriggerDetectFinding,
	TriggerFuzzerComplete,
	TriggerRequestCaptured,
}

// Limits on the shape of an installed package.
const (
	MaxIDLen          = 64
	MaxNameLen        = 80
	MaxVersionLen     = 32
	MaxDescriptionLen = 400
	MaxEntrypointLen  = 64
	MaxRevisions      = 50
)

var (
	// idPattern is the plugin name pattern, reused so an operator learns one rule for
	// both kinds of extension. It excludes '/', '\' and '.', which is what makes an ID
	// safe to use as a path component — but see Store, which checks it again at the
	// join rather than trusting that this ran.
	idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

	// entrypointPattern admits a bare filename only. A separator here would be a path
	// traversal, and a subdirectory would imply a module system that does not exist.
	entrypointPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.js$`)
)

// DefaultEntrypoint is used when a manifest omits one.
const DefaultEntrypoint = "index.js"

// ManifestLimits is the author's requested budget. Every field is optional; a zero
// means "take the default". Values are requests, not guarantees: the operator may
// lower any of them, and jsruntime.Limits.Normalize clamps the result to its ceilings.
// Nothing here can raise a limit.
type ManifestLimits struct {
	TimeoutMs      int `json:"timeoutMs,omitempty"`
	MemoryMB       int `json:"memoryMb,omitempty"`
	MaxCalls       int `json:"maxCalls,omitempty"`
	MaxSendCalls   int `json:"maxSendCalls,omitempty"`
	MaxLogBytes    int `json:"maxLogBytes,omitempty"`
	MaxResultBytes int `json:"maxResultBytes,omitempty"`
}

// Manifest is the author-owned half of a package: what this automation is and what it
// expects. It cannot request a capability — the SDK version selects a Joro-owned bundle,
// and that indirection is the whole point. An operator reviewing a package therefore
// reviews code, triggers and limits, not a permission matrix.
type Manifest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`

	SDKVersion string `json:"sdkVersion"`
	Entrypoint string `json:"entrypoint,omitempty"`

	Triggers []string        `json:"triggers,omitempty"`
	Limits   *ManifestLimits `json:"limits,omitempty"`

	// MinIntervalMs paces an event trigger: the shortest gap between two runs. Not in
	// Limits because it is the one value where the conservative choice is the larger
	// one, and Limits combines by taking the smaller of author and operator.
	MinIntervalMs int `json:"minIntervalMs,omitempty"`
}

// Normalize fills defaults and trims. Called before Validate so a manifest that omits
// optional fields is accepted rather than corrected by the operator.
func (m *Manifest) Normalize() {
	m.ID = strings.ToLower(strings.TrimSpace(m.ID))
	m.Name = strings.TrimSpace(m.Name)
	m.Version = strings.TrimSpace(m.Version)
	m.Description = strings.TrimSpace(m.Description)
	m.SDKVersion = strings.TrimSpace(m.SDKVersion)
	m.Entrypoint = strings.TrimSpace(m.Entrypoint)

	if m.SDKVersion == "" {
		m.SDKVersion = SDKVersion1
	}
	if m.Entrypoint == "" {
		m.Entrypoint = DefaultEntrypoint
	}
	if m.Name == "" {
		m.Name = m.ID
	}
	if m.Version == "" {
		m.Version = "0.0.0"
	}
	if len(m.Triggers) == 0 {
		m.Triggers = []string{TriggerManual}
	}

	seen := make(map[string]struct{}, len(m.Triggers))
	kept := m.Triggers[:0]
	for _, t := range m.Triggers {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		kept = append(kept, t)
	}
	m.Triggers = kept
}

// Validate reports why a manifest cannot be installed. Messages name the field and the
// rule, because the audience is as often a language model that generated the package as
// a person who wrote it.
func (m *Manifest) Validate() error {
	switch {
	case m.ID == "":
		return fmt.Errorf("id is required")
	case len(m.ID) > MaxIDLen:
		return fmt.Errorf("id is %d characters, over the %d limit", len(m.ID), MaxIDLen)
	case !idPattern.MatchString(m.ID):
		return fmt.Errorf("id %q is invalid: use lowercase letters, digits, hyphen and "+
			"underscore, starting with a letter or digit", m.ID)
	case len(m.Name) > MaxNameLen:
		return fmt.Errorf("name is %d characters, over the %d limit", len(m.Name), MaxNameLen)
	case len(m.Version) > MaxVersionLen:
		return fmt.Errorf("version is %d characters, over the %d limit", len(m.Version), MaxVersionLen)
	case len(m.Description) > MaxDescriptionLen:
		return fmt.Errorf("description is %d characters, over the %d limit",
			len(m.Description), MaxDescriptionLen)
	case m.SDKVersion != SDKVersion1:
		return fmt.Errorf("sdkVersion %q is not supported by this build of Joro (supported: %q)",
			m.SDKVersion, SDKVersion1)
	case len(m.Entrypoint) > MaxEntrypointLen:
		return fmt.Errorf("entrypoint is %d characters, over the %d limit",
			len(m.Entrypoint), MaxEntrypointLen)
	case !entrypointPattern.MatchString(m.Entrypoint):
		return fmt.Errorf("entrypoint %q must be a single .js filename with no directory "+
			"separator: there is no module loader, so a package is one bundled script",
			m.Entrypoint)
	}

	for _, t := range m.Triggers {
		if !slices.Contains(Triggers, t) {
			return fmt.Errorf("unknown trigger %q (known: %s)", t, strings.Join(Triggers, ", "))
		}
	}
	return nil
}

// Revision records one version of the source.
//
// Metadata only, by design. "Did the code change?" is answered here; "what exactly ran?"
// is answered by the run log, which retains each run's source verbatim along with its
// hash. Keeping full past source here too would be a third content store answering a
// question the other two already cover between them.
type Revision struct {
	Hash  string    `json:"hash"`
	At    time.Time `json:"at"`
	Bytes int       `json:"bytes"`
}

// LastRun is a pointer to the most recent run, for the list view.
type LastRun struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// State is the operator-owned half of a package, kept in a separate file from the
// manifest so that installing an update never silently reverts a limit the operator
// lowered or a trigger they switched off.
type State struct {
	// Enabled arms the automation: an agent may invoke it and the dispatcher may
	// trigger it. The operator can always run a disabled automation from the UI,
	// because testing has to come before arming.
	Enabled bool `json:"enabled"`

	// Paused is set by the runaway breaker, never by the operator. It is separate from
	// Enabled so that resuming restores the operator's original intent rather than
	// asking them to remember it, and it persists so a restart does not silently
	// re-arm something that was looping.
	Paused       bool   `json:"paused,omitempty"`
	PausedReason string `json:"pausedReason,omitempty"`

	// TriggersDisabled switches off individual triggers the manifest declares: true
	// disables, and an absent key means armed — so a manifest that adds a trigger in an
	// update does not arm it behind an operator who had switched a different one off.
	//
	// Named for what a true means. The polarity is the whole content of this field, and
	// a reader who has to infer it from a call site will eventually infer it backwards.
	TriggersDisabled map[string]bool `json:"triggersDisabled,omitempty"`

	// Limits narrows the manifest's request. Never widens: see Automation.Limits.
	Limits *ManifestLimits `json:"limits,omitempty"`

	// HostAllow bounds where this automation's runs may send, as globs matched by the
	// capability guard. It exists for trigger-fired runs, which carry no launching token
	// and are otherwise bounded by scope alone. Empty means "scope only".
	HostAllow []string `json:"hostAllow,omitempty"`

	// MinIntervalMs slows a trigger further than the manifest asked. Combined with
	// max, so the operator can only ever add space between runs.
	MinIntervalMs int `json:"minIntervalMs,omitempty"`

	InstalledAt time.Time  `json:"installedAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	Revisions   []Revision `json:"revisions,omitempty"`
	LastRun     *LastRun   `json:"lastRun,omitempty"`
}

// Automation is a loaded package: what the author wrote, what the operator decided, and
// the source itself.
type Automation struct {
	Manifest   Manifest `json:"manifest"`
	State      State    `json:"state"`
	Source     string   `json:"source,omitempty"`
	SourceHash string   `json:"sourceHash"`
}

// Summary is an Automation without its source, for lists. Source is withheld rather
// than merely omitted: a capability that could read other automations' code would be a
// lateral channel between tokens, which is the same reason the run log stays UI-only.
type Summary struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Description  string    `json:"description,omitempty"`
	SDKVersion   string    `json:"sdkVersion"`
	Triggers     []string  `json:"triggers"`
	Armed        []string  `json:"armed"`
	Enabled      bool      `json:"enabled"`
	Paused       bool      `json:"paused,omitempty"`
	PausedReason string    `json:"pausedReason,omitempty"`
	SourceHash   string    `json:"sourceHash"`
	SourceBytes  int       `json:"sourceBytes"`
	InstalledAt  time.Time `json:"installedAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Revisions    int       `json:"revisions"`
	LastRun      *LastRun  `json:"lastRun,omitempty"`
}

// Summarize projects an Automation for a list view.
func (a *Automation) Summarize() Summary {
	return Summary{
		ID:           a.Manifest.ID,
		Name:         a.Manifest.Name,
		Version:      a.Manifest.Version,
		Description:  a.Manifest.Description,
		SDKVersion:   a.Manifest.SDKVersion,
		Triggers:     slices.Clone(a.Manifest.Triggers),
		Armed:        a.ArmedTriggers(),
		Enabled:      a.State.Enabled,
		Paused:       a.State.Paused,
		PausedReason: a.State.PausedReason,
		SourceHash:   a.SourceHash,
		SourceBytes:  len(a.Source),
		InstalledAt:  a.State.InstalledAt,
		UpdatedAt:    a.State.UpdatedAt,
		Revisions:    len(a.State.Revisions),
		LastRun:      a.State.LastRun,
	}
}

// Runnable reports whether an agent or the dispatcher may run this. The operator's own
// manual run deliberately does not consult it.
func (a *Automation) Runnable() bool { return a.State.Enabled && !a.State.Paused }

// ArmedTriggers lists the event triggers currently live: declared by the manifest, not
// switched off by the operator, and only while the automation is runnable. Manual is
// excluded — it is not something the dispatcher watches for.
func (a *Automation) ArmedTriggers() []string {
	if !a.Runnable() {
		return nil
	}
	var out []string
	for _, t := range a.Manifest.Triggers {
		if t == TriggerManual {
			continue
		}
		if a.State.TriggersDisabled[t] {
			continue
		}
		out = append(out, t)
	}
	return out
}

// Limits resolves the budget one run of this automation gets.
//
// The author asks, the operator narrows, the runtime clamps. Taking the smaller of each
// pair rather than letting either win outright is what makes "an automation can never
// raise its own limits" true no matter which side was edited last.
func (a *Automation) Limits() jsruntime.Limits {
	return narrower(a.Manifest.Limits, a.State.Limits).toRuntime().Normalize()
}

// narrower returns the field-wise minimum of two optional budgets, treating zero as
// "unspecified" rather than as the smallest value.
func narrower(a, b *ManifestLimits) ManifestLimits {
	var out ManifestLimits
	if a == nil && b == nil {
		return out
	}
	if a == nil {
		return *b
	}
	if b == nil {
		return *a
	}
	pick := func(x, y int) int {
		switch {
		case x <= 0:
			return y
		case y <= 0:
			return x
		default:
			return min(x, y)
		}
	}
	out.TimeoutMs = pick(a.TimeoutMs, b.TimeoutMs)
	out.MemoryMB = pick(a.MemoryMB, b.MemoryMB)
	out.MaxCalls = pick(a.MaxCalls, b.MaxCalls)
	out.MaxSendCalls = pick(a.MaxSendCalls, b.MaxSendCalls)
	out.MaxLogBytes = pick(a.MaxLogBytes, b.MaxLogBytes)
	out.MaxResultBytes = pick(a.MaxResultBytes, b.MaxResultBytes)
	return out
}

func (l ManifestLimits) toRuntime() jsruntime.Limits {
	return jsruntime.Limits{
		Timeout:        time.Duration(l.TimeoutMs) * time.Millisecond,
		MemoryBytes:    int64(l.MemoryMB) << 20,
		MaxCalls:       l.MaxCalls,
		MaxSendCalls:   l.MaxSendCalls,
		MaxLogBytes:    l.MaxLogBytes,
		MaxResultBytes: l.MaxResultBytes,
	}
}
