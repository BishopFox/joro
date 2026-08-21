package jsautomation

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/jsruntime"
	"github.com/BishopFox/joro/internal/localcmd"
)

// SDKVersion1 binds to the automation-v1 bundle. A manifest declares which SDK
// contract it expects; Joro decides what that contract grants. Adding a method to the
// SDK follows ordinary compatibility rules, but a materially more dangerous class of
// authority takes a new version rather than appearing inside this one.
const SDKVersion1 = "1"

// The two kinds of installed automation.
//
// A package is either a sandboxed script or a local command, and the kind decides which
// half of this package's machinery runs it. Everything around that — the store, the
// dispatcher, the trigger set, the lens, the operator's overrides, the run log — is
// shared, which is the whole reason this is a field rather than a second package.
//
// KindJS is the zero value after Normalize, and that is load-bearing rather than
// convenient: the capability that lets an agent install a package has no kind argument,
// so an agent-authored manifest is a script by construction and cannot become a command
// by omitting a field. See Store.InstallAs, which refuses the pair outright.
const (
	KindJS      = "js"
	KindCommand = "command"
)

// Kinds lists the valid Manifest.Kind values, script first.
var Kinds = []string{KindJS, KindCommand}

// Trigger names. These are Joro's own event type strings, not a parallel vocabulary —
// an automation subscribes to the thing that already happens.
//
// callback.interaction is deliberately absent. Every callback listener is constructed
// in listener mode, scripting exists only in proxy mode, and the team relay forwards
// nothing but team.* — so a proxy-mode dispatcher would be waiting for an event that
// structurally cannot arrive. Offering it would be a trigger that silently never fires.
const (
	TriggerManual          = "manual"
	TriggerRequestSelected = "request.selected"
	TriggerRequestCaptured = "request.captured"
	TriggerDetectFinding   = "detect.finding"
	TriggerFuzzerComplete  = "fuzzer.complete"
)

// Triggers lists every subscribable trigger, in the order the UI shows them: manual
// first, then cheapest-to-reason-about to most consequential.
var Triggers = []string{
	TriggerManual,
	TriggerRequestSelected,
	TriggerDetectFinding,
	TriggerFuzzerComplete,
	TriggerRequestCaptured,
}

// TriggerLens labels a run the request/response viewer started to render a lens tab.
// Not in Triggers: the Lens declaration is what enables it, so there is nothing for an
// operator to switch on here. It names why a run happened, and selects the send-free
// principal in Manager.Invoke.
const TriggerLens = "lens"

// Which half of a transaction a lens renders.
const (
	LensPartRequest  = "request"
	LensPartResponse = "response"
	LensPartBoth     = "both"
)

// LensParts lists the valid Lens.Part values, in the order the UI shows them.
var LensParts = []string{LensPartRequest, LensPartResponse, LensPartBoth}

// Limits on the shape of an installed package.
const (
	MaxIDLen          = 64
	MaxNameLen        = 80
	MaxVersionLen     = 32
	MaxDescriptionLen = 400
	MaxEntrypointLen  = 64
	MaxLensLabelLen   = 24
	MaxRevisions      = 50
)

// MaxAgentPackages bounds how many packages a capability may leave in the operator's
// list. One directory per attempt, each up to the operator's program-size limit, is a
// list nobody reads — and reviewing it is the only thing that makes storing one useful.
const MaxAgentPackages = 32

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
// lower any of them per automation or globally, and jsruntime resolves the result
// against its own defaults and ceilings. Nothing here can raise a limit.
//
// An alias rather than a type of its own: the author's request, the operator's global
// budget, the wire and ~/.joro/automation.json all carry the same six fields in the same
// units, and a second declaration of them is a table someone has to keep in step.
type ManifestLimits = jsruntime.Budget

// Lens declares that this automation renders a tab in the request/response viewer.
//
// A lens is a pure function of bytes to text: the viewer hands it the bytes it is
// already displaying and renders what comes back. Its run holds no send grants.
type Lens struct {
	Label string `json:"label"`
	Part  string `json:"part"` // request | response | both
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

	// Kind selects the execution half. Empty normalizes to KindJS.
	Kind string `json:"kind,omitempty"`

	// SDKVersion and Entrypoint belong to a script and are empty on a command.
	//
	// SDKVersion names the authority contract a run is bound to, and a command has
	// none: its authority is not a bundle Joro grants but the operator's decision to
	// arm it. Carrying a version that selects nothing would suggest a contract exists
	// where the honest answer is that the operator is the contract.
	SDKVersion string `json:"sdkVersion,omitempty"`
	Entrypoint string `json:"entrypoint,omitempty"`

	// Command is the whole body of a KindCommand package: what to run, what to feed
	// it, and what environment it gets. Nil on a script.
	//
	// It lives in the manifest rather than in a file beside it because a spec is
	// structured data a form edits, where a script is text an author writes — and
	// jsautomation.Store keeps the script in a real .js file precisely because a
	// JSON-escaped source string is hostile to reading. A spec has the opposite
	// shape, so it belongs here and Render() is what makes it readable.
	Command *localcmd.Spec `json:"command,omitempty"`

	Triggers []string        `json:"triggers,omitempty"`
	Limits   *ManifestLimits `json:"limits,omitempty"`

	// Lens, when set, adds a viewer tab. The operator can retitle it, point it at the
	// other half of the transaction, or reorder it; see State.
	Lens *Lens `json:"lens,omitempty"`

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
	m.Kind = strings.ToLower(strings.TrimSpace(m.Kind))

	if m.Kind == "" {
		m.Kind = KindJS
	}
	if m.Kind == KindCommand {
		// Neither field means anything for a command, and clearing them here rather
		// than rejecting them in Validate keeps an already-installed package loadable
		// after a hand edit — the same choice the lens/trigger drop below makes.
		m.SDKVersion = ""
		m.Entrypoint = ""
		if m.Command != nil {
			m.Command.Normalize()
		}
	} else {
		m.Command = nil
		if m.SDKVersion == "" {
			m.SDKVersion = SDKVersion1
		}
		if m.Entrypoint == "" {
			m.Entrypoint = DefaultEntrypoint
		}
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

	if m.Lens != nil {
		m.Lens.Label = strings.TrimSpace(m.Lens.Label)
		m.Lens.Part = strings.ToLower(strings.TrimSpace(m.Lens.Part))
		if m.Lens.Part == "" {
			m.Lens.Part = LensPartResponse
		}

		// A lens is started by the viewer, not by an event, so an event trigger declared
		// beside one is a switch that does nothing. Dropped here rather than rejected in
		// Validate, which runs on every Load: refusing the pair would make an
		// already-installed package unloadable. The two the operator starts survive — a
		// lens in History's context menu is a coherent pairing.
		m.Triggers = slices.DeleteFunc(m.Triggers, dispatched)
		if len(m.Triggers) == 0 {
			m.Triggers = []string{TriggerManual}
		}
	}
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
	case !slices.Contains(Kinds, m.Kind):
		return fmt.Errorf("unknown kind %q (known: %s)", m.Kind, strings.Join(Kinds, ", "))
	}

	if err := m.validateKind(); err != nil {
		return err
	}

	for _, t := range m.Triggers {
		if !slices.Contains(Triggers, t) {
			return fmt.Errorf("unknown trigger %q (known: %s)", t, strings.Join(Triggers, ", "))
		}
	}

	if m.Lens != nil {
		switch {
		case m.Lens.Label == "":
			return fmt.Errorf("lens.label is required: it is the viewer tab's title")
		case len(m.Lens.Label) > MaxLensLabelLen:
			return fmt.Errorf("lens.label is %d characters, over the %d limit; it has to fit a tab",
				len(m.Lens.Label), MaxLensLabelLen)
		case !slices.Contains(LensParts, m.Lens.Part):
			return fmt.Errorf("unknown lens.part %q (known: %s)", m.Lens.Part, strings.Join(LensParts, ", "))
		}
	}
	return nil
}

// validateKind checks the fields that belong to one kind and must be absent on the
// other.
//
// Split out of Validate because the two halves read as two rules and reviewing them
// together is what catches a field drifting into the wrong kind. Note that Normalize has
// already cleared the mismatched fields, so on the ordinary path these cases only fire
// for a caller that validates a manifest it built by hand.
func (m *Manifest) validateKind() error {
	if m.Kind == KindCommand {
		switch {
		case m.Command == nil:
			return fmt.Errorf("kind %q requires a command block naming what to run", KindCommand)
		case m.Entrypoint != "":
			return fmt.Errorf("a %s automation has no entrypoint: its body is the command block", KindCommand)
		case m.SDKVersion != "":
			return fmt.Errorf("a %s automation has no sdkVersion: it calls no SDK, and what it may do "+
				"is decided by your enabling it rather than by a grant bundle", KindCommand)
		}
		return m.Command.Validate()
	}

	switch {
	case m.Command != nil:
		return fmt.Errorf("a %s automation has no command block: its body is the script", KindJS)
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
	return nil
}

// IsCommand reports whether this package's body is a local command rather than a script.
// A predicate rather than a comparison at each site, so the several places that branch on
// it cannot disagree about what the zero value means.
func (m *Manifest) IsCommand() bool { return m.Kind == KindCommand }

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

	// Outcome is Reason's stable code. Omitted when empty so a sidecar written before
	// the field existed stays byte-identical until its next run; withOutcome fills it
	// in on the way out, so no reader sees the gap.
	Outcome string `json:"outcome,omitempty"`
}

// withOutcome derives a missing Outcome from Reason, for a sidecar written before the
// field existed. Applied on read rather than by migrating every joro.state.json on
// startup: the value is a pure function of one already stored there, so there is nothing
// to migrate and nothing to lose by leaving the file alone.
func (l *LastRun) withOutcome() *LastRun {
	if l == nil {
		return nil
	}
	if l.Outcome == "" {
		out := *l
		out.Outcome = jsruntime.OutcomeFor(out.Reason)
		return &out
	}
	return l
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

	// Author names the automation token whose capability call last wrote this package's
	// code. Empty means the operator, which is also what a package installed before this
	// field existed reads as — both mean "not agent-authored".
	//
	// Display only. Nothing authorizes on it: whether a capability may replace a package
	// turns on whether the operator has enabled it, and on nothing else. It is here so
	// the operator can see whose code they are about to arm.
	//
	// In State rather than Manifest because the manifest is submitted content: a package
	// that could name its own author could name the operator.
	Author string `json:"author,omitempty"`

	// Overrides for the manifest's Lens. Empty means take the author's value.
	// LensOrder sorts the viewer's tabs; equal orders fall back to the label.
	LensLabel string `json:"lensLabel,omitempty"`
	LensPart  string `json:"lensPart,omitempty"`
	LensOrder int    `json:"lensOrder,omitempty"`

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

// EffectiveLens resolves the lens the viewer should render: the author's declaration
// with the operator's overrides applied. Nil when the automation declares none.
//
// The merge happens here rather than in the frontend so a caller never has to hold both
// halves and decide which wins.
func (a *Automation) EffectiveLens() *Lens {
	if a.Manifest.Lens == nil {
		return nil
	}
	l := *a.Manifest.Lens
	if s := strings.TrimSpace(a.State.LensLabel); s != "" {
		l.Label = s
	}
	if s := strings.ToLower(strings.TrimSpace(a.State.LensPart)); slices.Contains(LensParts, s) {
		l.Part = s
	}
	return &l
}

// Summary is an Automation without its source, for lists. Source is withheld rather
// than merely omitted: a capability that could read other automations' code would be a
// lateral channel between tokens, which is the same reason the run log stays UI-only.
type Summary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Kind        string `json:"kind"`
	SDKVersion  string `json:"sdkVersion,omitempty"`

	// Command is the one-line rendering of a command package's argv, so a list view can
	// show what would run without holding the whole spec. Empty for a script.
	//
	// The full spec is deliberately not here. Summary withholds a script's Source
	// because a capability able to read another automation's code would be a lateral
	// channel between tokens, and a command's argv is the same kind of thing — it names
	// paths on the operator's machine.
	Command string `json:"command,omitempty"`

	Triggers     []string  `json:"triggers"`
	Armed        []string  `json:"armed"`
	Lens         *Lens     `json:"lens,omitempty"`
	LensOrder    int       `json:"lensOrder,omitempty"`
	Enabled      bool      `json:"enabled"`
	Paused       bool      `json:"paused,omitempty"`
	PausedReason string    `json:"pausedReason,omitempty"`
	SourceHash   string    `json:"sourceHash"`
	SourceBytes  int       `json:"sourceBytes"`
	Author       string    `json:"author,omitempty"`
	InstalledAt  time.Time `json:"installedAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Revisions    int       `json:"revisions"`
	LastRun      *LastRun  `json:"lastRun,omitempty"`
}

// Summarize projects an Automation for a list view.
func (a *Automation) Summarize() Summary {
	var command string
	if a.Manifest.Command != nil {
		command = a.Manifest.Command.Summary()
	}
	return Summary{
		ID:          a.Manifest.ID,
		Name:        a.Manifest.Name,
		Version:     a.Manifest.Version,
		Description: a.Manifest.Description,
		Kind:        a.Manifest.Kind,
		SDKVersion:  a.Manifest.SDKVersion,
		Command:     command,
		Triggers:    slices.Clone(a.Manifest.Triggers),
		// Never nil: the field is a JSON array in the client's type, and a lens or a
		// manual-only automation arms nothing.
		Armed:        orEmpty(a.ArmedTriggers()),
		Lens:         a.EffectiveLens(),
		LensOrder:    a.State.LensOrder,
		Enabled:      a.State.Enabled,
		Paused:       a.State.Paused,
		PausedReason: a.State.PausedReason,
		SourceHash:   a.SourceHash,
		SourceBytes:  len(a.Source),
		Author:       a.State.Author,
		InstalledAt:  a.State.InstalledAt,
		UpdatedAt:    a.State.UpdatedAt,
		Revisions:    len(a.State.Revisions),
		LastRun:      a.State.LastRun.withOutcome(),
	}
}

// orEmpty returns a non-nil slice, so a JSON field declared as an array never encodes
// as null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Runnable reports whether an agent or the dispatcher may run this. The operator's own
// manual run deliberately does not consult it.
func (a *Automation) Runnable() bool { return a.State.Enabled && !a.State.Paused }

// dispatched reports whether the Dispatcher watches this trigger. Manual and
// request.selected are excluded because the operator starts both. One predicate rather than
// two spellings of it: Normalize drops exactly this set from a lens, and the two answers must
// not drift.
func dispatched(t string) bool {
	return t != TriggerManual && t != TriggerRequestSelected
}

// ArmedTriggers lists the event triggers currently live: declared by the manifest, not
// switched off by the operator, and only while the automation is runnable. Manual and
// request.selected are excluded — the operator starts both, so the dispatcher does not
// watch for them.
func (a *Automation) ArmedTriggers() []string {
	if !a.Runnable() {
		return nil
	}
	var out []string
	for _, t := range a.Manifest.Triggers {
		if !dispatched(t) {
			continue
		}
		if a.State.TriggersDisabled[t] {
			continue
		}
		out = append(out, t)
	}
	return out
}

// RequestedBudget is what this automation asks for: the author's manifest narrowed by
// the operator's per-automation override.
//
// Taking the smaller of each pair rather than letting either win outright is what makes
// "an automation can never raise its own limits" true no matter which side was edited
// last. Deliberately **not** normalized: a zero has to stay a zero here, or the shipped
// default would be baked in as a hard value and the operator's global budget could never
// reach an automation that declares nothing. Resolution happens once, in Manager.Run.
func (a *Automation) RequestedBudget() ManifestLimits {
	return narrower(a.Manifest.Limits, a.State.Limits)
}

// EffectiveBudget is what a run of this automation would actually get under the
// operator's policy. For display: the editor shows the author's request, the operator's
// per-automation override and this, so nobody has to work out which one wins.
func (a *Automation) EffectiveBudget(p jsruntime.BudgetPolicy) ManifestLimits {
	return a.RequestedBudget().Limits().NormalizeWith(p).Budget()
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
