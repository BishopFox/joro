package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/capreg"
	"github.com/BishopFox/joro/internal/jsautomation"
	"github.com/BishopFox/joro/internal/jsruntime"
	"github.com/BishopFox/joro/internal/localcmd"
)

// maxAutomationBody bounds a request on the automation control plane. Sized for the
// largest of them — one carrying automation source — from the program-size ceiling the
// budget offers, with room for a manifest beside it, so the program limit is the one that
// reports rather than this. Passed to decodeJSONLimit; see the tiers in decode.go.
const maxAutomationBody = jsruntime.CapSourceBytes + (1 << 19)

// decodeAutomationJSON is decodeJSON at the automation plane's own body cap.
func decodeAutomationJSON(r *http.Request, dst any) error {
	return decodeJSONLimit(r, dst, maxAutomationBody)
}

// The script run log, over REST.
//
// UI-only, like the rest of the automation control plane: an automation client reaches
// Joro on the MCP port, whose mux has no /api/v1 routes, so a bearer token cannot read
// these. That matters more here than elsewhere — the run log holds the verbatim source
// of everything every token has run, and a script being able to read other scripts
// would make it a lateral channel between tokens.
//
// These exist in the same pass as script.run rather than waiting for the authoring UI,
// because retaining a script's source with no way to read it back is not a feature. The
// question the log answers — which exact code did an agent run against a client's
// systems — is the one an operator most needs after the fact.

// requireAutomations reports whether installed automations exist at all — either kind —
// writing the JSON 404 if not.
//
// Three gates rather than one, because there are three ways to be switched off and each
// has a different remedy. An operator sent to the wrong flag has been told something
// worse than nothing, so every message names the switch that would change the answer:
//
//	requireAutomation   --no-automation, nothing about automation is registered
//	requireAutomations  neither --automation-scripting nor --automation-commands
//	requireScripting    the JavaScript half specifically
//
// The frontend distinguishes them by looking for "--automation-scripting" in the text,
// which both of the latter two carry — so the message can gain detail without the client
// having to learn a new one.
func (s *APIServer) requireAutomations(w http.ResponseWriter) bool {
	if !s.requireAutomation(w) {
		return false
	}
	if s.scriptManager == nil {
		writeError(w, http.StatusNotFound,
			"installed automations are not enabled on this instance; start Joro with "+
				"--automation-scripting for sandboxed scripts, or --automation-commands to run "+
				"local commands")
		return false
	}
	return true
}

// requireScripting reports whether the JavaScript half is available.
//
// Distinct from requireAutomations because the manager also exists for commands alone: an
// operator running with only --automation-commands has installed automations but no script
// runtime, and "installed automations are not enabled" would be false.
func (s *APIServer) requireScripting(w http.ResponseWriter) bool {
	if !s.requireAutomations(w) {
		return false
	}
	if !s.scriptingEnabled() {
		writeError(w, http.StatusNotFound,
			"script automation is not enabled on this instance; start Joro with --automation-scripting")
		return false
	}
	return true
}

func (s *APIServer) handleListScriptRuns(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomations(w) {
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 200)

	runs, total := s.scriptManager.Runs().List(offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"runs":   runs,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleGetScriptRun(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomations(w) {
		return
	}
	run, ok := s.scriptManager.Runs().Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no such run")
		return
	}
	// Unlike the list, this carries the source. It is the whole point of the endpoint.
	writeJSON(w, http.StatusOK, run)
}

func (s *APIServer) handleClearScriptRuns(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomations(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": s.scriptManager.Runs().Clear()})
}

// handleGetRunArtifact serves one file from a command run's working directory.
//
// It exists because without it the headline use is only half a feature: a scanner's whole
// output is the report directory it writes, and a run that lists file names nobody can open
// has told the operator what they are missing rather than giving it to them.
//
// What it serves is anything inside that one run's directory, which is a slightly wider
// contract than the artifact list the run reported — the input files Joro itself wrote are
// reachable too, since they are also in there. That is deliberate rather than overlooked:
// the directory holds only what Joro put there and what the command produced, so "inside
// this run's directory" is the whole containment, and it is a property of the path rather
// than of a list someone has to keep in step with it.
//
// The path is resolved by jsautomation.ArtifactPath, which owns the scratch layout and
// validates the path — this handler deliberately does not join anything itself. Served as an
// attachment with a generic content type and nosniff, so a file a third-party tool wrote is
// downloaded rather than rendered.
func (s *APIServer) handleGetRunArtifact(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomations(w) {
		return
	}
	path, err := s.scriptManager.ArtifactPath(r.PathValue("id"), r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such artifact")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	http.ServeFile(w, r, path)
}

// ---- Installed automations ----

// packages returns the installed-automation store, writing the 404 if unavailable.
func (s *APIServer) packages(w http.ResponseWriter) *jsautomation.Store {
	if !s.requireAutomations(w) {
		return nil
	}
	st := s.scriptManager.Packages()
	if st == nil {
		writeError(w, http.StatusNotFound, "installed automations are unavailable on this instance")
		return nil
	}
	return st
}

// writeStoreError maps the store's sentinels onto status codes. A hash mismatch is 409:
// the request was well-formed and the caller's view of the world was simply stale.
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jsautomation.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such automation")
	case errors.Is(err, jsautomation.ErrExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, jsautomation.ErrHashMismatch):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func (s *APIServer) handleListScripts(w http.ResponseWriter, r *http.Request) {
	if s.packages(w) == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scripts":  s.scriptManager.List(),
		"triggers": jsautomation.Triggers,
		"bundle":   jsautomation.BundleVersion,
		"kinds":    jsautomation.Kinds,

		// The command vocabulary, served rather than restated in the frontend — the same
		// reason the budget serves its specs. A stdin mode or a placeholder added in Go
		// then appears in the editor's selects with no client change, and a client can
		// never offer one the server would refuse.
		"scripting": s.scriptingEnabled(),
		"commands": map[string]any{
			"enabled":     s.commandsEnabled(),
			"stdinModes":  localcmd.StdinModes,
			"outputModes": localcmd.OutputModes,
			"fileParts":   localcmd.FileParts,

			// What each placeholder is, and which triggers supply one. Two sources
			// because they are two packages' knowledge: localcmd owns the grammar it
			// enforces, jsautomation owns which trigger populates what. The editor
			// renders both and hardcodes neither, which is what stopped the old
			// hand-written paragraph from drifting away from checkCaptured.
			"placeholders": localcmd.PlaceholderDocs(),
			"availability": jsautomation.CommandPlaceholderAvailability(),
			"inputToken":   localcmd.PlaceholderInput,
		},
	})
}

func (s *APIServer) handleGetScript(w http.ResponseWriter, r *http.Request) {
	store := s.packages(w)
	if store == nil {
		return
	}
	a, err := store.Load(r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// With source: this is the operator reading their own automation, which is the
	// point of keeping it as a real file in the first place.
	//
	// effectiveLimits rides along for the same reason EffectiveLens does: the budget is
	// the author's request narrowed by the operator's override and then held to the
	// global, and resolving it here means no caller has to hold three halves and decide
	// which wins.
	writeJSON(w, http.StatusOK, struct {
		*jsautomation.Automation
		EffectiveLimits jsautomation.ManifestLimits `json:"effectiveLimits"`
	}{a, a.EffectiveBudget(s.scriptManager.Budget())})
}

type scriptWriteBody struct {
	Manifest jsautomation.Manifest `json:"manifest"`
	Source   string                `json:"source"`
	// ExpectedHash is required to replace the source of an armed automation.
	ExpectedHash string `json:"expectedHash,omitempty"`
}

func (s *APIServer) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	store := s.packages(w)
	if store == nil {
		return
	}
	var body scriptWriteBody
	if err := decodeAutomationJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a, err := store.Install(body.Manifest, body.Source)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	log.Printf("[automation] installed %s v%s (disabled)", a.Manifest.ID, a.Manifest.Version)
	writeJSON(w, http.StatusCreated, a)
}

func (s *APIServer) handleUpdateScript(w http.ResponseWriter, r *http.Request) {
	store := s.packages(w)
	if store == nil {
		return
	}
	var body scriptWriteBody
	if err := decodeAutomationJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	if body.Manifest.ID == "" {
		body.Manifest.ID = id
	}
	a, err := store.Update(id, body.Manifest, body.Source, body.ExpectedHash)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *APIServer) handleDeleteScript(w http.ResponseWriter, r *http.Request) {
	store := s.packages(w)
	if store == nil {
		return
	}
	id := r.PathValue("id")
	if err := store.Delete(id); err != nil {
		writeStoreError(w, err)
		return
	}
	// Its stored state has no meaning without the code that wrote it.
	if s.automationStorage != nil {
		s.automationStorage.Drop(id)
	}
	if s.scriptTriggers != nil {
		s.scriptTriggers.Wake()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *APIServer) handleSetScriptEnabled(w http.ResponseWriter, r *http.Request) {
	store := s.packages(w)
	if store == nil {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeAutomationJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a, err := store.SetState(r.PathValue("id"), func(st *jsautomation.State) {
		st.Enabled = body.Enabled
		// Enabling clears a breaker pause. The operator is answering the question the
		// pause asked, and leaving it set would make Enable appear to do nothing.
		if body.Enabled {
			st.Paused = false
			st.PausedReason = ""
		}
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.scriptTriggers != nil {
		s.scriptTriggers.Wake()
	}
	writeJSON(w, http.StatusOK, a.Summarize())
}

func (s *APIServer) handleSetScriptPrefs(w http.ResponseWriter, r *http.Request) {
	store := s.packages(w)
	if store == nil {
		return
	}
	// Pointers so an absent field is left alone rather than zeroed, the same reason
	// handleSetProjectPrefs takes *bool.
	var body struct {
		Limits           *jsautomation.ManifestLimits `json:"limits"`
		TriggersDisabled map[string]bool              `json:"triggersDisabled"`
		HostAllow        *[]string                    `json:"hostAllow"`
		LensLabel        *string                      `json:"lensLabel"`
		LensPart         *string                      `json:"lensPart"`
		LensOrder        *int                         `json:"lensOrder"`
	}
	if err := decodeAutomationJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// An empty string clears the override back to the manifest's value; anything else
	// has to name a real part, for the same reason an unknown trigger is rejected below.
	if body.LensPart != nil && *body.LensPart != "" && !slices.Contains(jsautomation.LensParts, *body.LensPart) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown lens part %q (known: %s)",
			*body.LensPart, strings.Join(jsautomation.LensParts, ", ")))
		return
	}
	// Reject an unknown trigger name rather than storing it. A typo would otherwise be
	// accepted with a 200 and silently mean "armed", which is the wrong direction for the
	// control an operator reaches for to switch a trigger off.
	for name := range body.TriggersDisabled {
		if !slices.Contains(jsautomation.Triggers, name) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"unknown trigger %q (known: %s)", name, strings.Join(jsautomation.Triggers, ", ")))
			return
		}
	}

	a, err := store.SetState(r.PathValue("id"), func(st *jsautomation.State) {
		if body.Limits != nil {
			st.Limits = body.Limits
		}
		if body.TriggersDisabled != nil {
			st.TriggersDisabled = body.TriggersDisabled
		}
		if body.HostAllow != nil {
			st.HostAllow = *body.HostAllow
		}
		if body.LensLabel != nil {
			st.LensLabel = strings.TrimSpace(*body.LensLabel)
		}
		if body.LensPart != nil {
			st.LensPart = *body.LensPart
		}
		if body.LensOrder != nil {
			st.LensOrder = *body.LensOrder
		}
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.scriptTriggers != nil {
		s.scriptTriggers.Wake()
	}
	writeJSON(w, http.StatusOK, a.Summarize())
}

// handleRunScript runs an automation or a piece of inline source, on the operator's
// behalf.
//
// Inline source is accepted here and nowhere else. This is the operator's own request
// through the same-origin UI, not an agent's, and an authoring surface that cannot run a
// draft before it is saved is not an authoring surface. It is also why a disabled
// automation may be run from here: reviewing something means being able to run it first.
func (s *APIServer) handleRunScript(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomations(w) {
		return
	}
	var body struct {
		ScriptID string          `json:"scriptId"`
		Source   string          `json:"source"`
		Input    json.RawMessage `json:"input"`
		// Trigger labels the run in the log. Defaults to triggerUI.
		Trigger      string `json:"trigger"`
		TimeoutMs    int    `json:"timeoutMs"`
		MaxCalls     int    `json:"maxCalls"`
		MaxSendCalls int    `json:"maxSendCalls"`
	}
	if err := decodeAutomationJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	trigger, ok := runTrigger(body.Trigger)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown trigger %q (known: %s, %s)",
			body.Trigger, strings.Join(jsautomation.Triggers, ", "), jsautomation.TriggerLens))
		return
	}

	var (
		run *jsautomation.Run
		err error
	)
	switch {
	case body.ScriptID != "":
		run, err = s.scriptManager.Invoke(r.Context(), jsautomation.InvokeRequest{
			ID:      body.ScriptID,
			Input:   body.Input,
			Caller:  jsautomation.AutomationPrincipal(body.ScriptID),
			Trigger: trigger,
			// Derived from the trigger rather than taken from the body, so the
			// guarantee belongs to the surface and not to what the client asked for.
			NoSend:      trigger == jsautomation.TriggerLens,
			OperatorRun: true,
		})
	case strings.TrimSpace(body.Source) != "":
		// Inline source is JavaScript, so this branch needs the script half specifically.
		// An operator running with only --automation-commands has no runtime to hand it
		// to, and should be told which flag rather than getting a run that reports the
		// runtime missing.
		if !s.requireScripting(w) {
			return
		}
		run, err = s.scriptManager.Run(r.Context(), jsautomation.RunRequest{
			Source: body.Source,
			Input:  body.Input,
			// A name for the audit trail and no policy, exactly like
			// AutomationPrincipal: no token launched this, so runPrincipal resolves
			// policy from the operator's own configuration rather than from a flag on a
			// token they never issued.
			Caller:  capability.Principal{TokenName: "operator"},
			Trigger: trigger,
			NoSend:  trigger == jsautomation.TriggerLens,
			Limits: jsruntime.Limits{
				Timeout:      time.Duration(body.TimeoutMs) * time.Millisecond,
				MaxCalls:     body.MaxCalls,
				MaxSendCalls: body.MaxSendCalls,
			},
		})
	default:
		writeError(w, http.StatusBadRequest, "provide either scriptId or source")
		return
	}

	switch {
	case errors.Is(err, jsautomation.ErrBusy), errors.Is(err, jsautomation.ErrCommandBusy):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, jsautomation.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such automation")
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, run)
	}
}

// triggerUI labels a run the operator started by hand, so the run list can tell it from
// an agent's ("mcp") and from a trigger firing.
const triggerUI = "ui"

// runTrigger validates the label a run is recorded under, defaulting to triggerUI.
func runTrigger(t string) (string, bool) {
	switch t := strings.TrimSpace(t); {
	case t == "":
		return triggerUI, true
	case t == triggerUI || t == jsautomation.TriggerLens || slices.Contains(jsautomation.Triggers, t):
		return t, true
	default:
		return "", false
	}
}

// handleScriptSDK is the authoring reference: every joro.* method, joined with the
// registered title, description and argument schema of the capability behind it.
//
// Generated from the same binding table that builds the injected shim and the grant
// bundle, so a method that exists is documented and a documented method exists. The
// model-facing description doubles as author documentation, which is the whole reason
// there is one source rather than three.
func (s *APIServer) handleScriptSDK(w http.ResponseWriter, r *http.Request) {
	if !s.requireScripting(w) {
		return
	}
	type entry struct {
		JS           string          `json:"js"`
		Capability   string          `json:"capability"`
		Title        string          `json:"title,omitempty"`
		Description  string          `json:"description,omitempty"`
		InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
		ArgsExample  json.RawMessage `json:"argsExample,omitempty"`
		SendsTraffic bool            `json:"sendsTraffic,omitempty"`
		Mutating     bool            `json:"mutating,omitempty"`
	}

	out := make([]entry, 0, len(jsruntime.Bindings))
	for _, b := range jsruntime.Bindings {
		e := entry{JS: "joro." + b.JS, Capability: b.Cap}
		if c, ok := s.capRegistry.Get(b.Cap); ok {
			e.Title, e.Description = c.Title, c.Description
			e.InputSchema, e.ArgsExample = c.InputSchema, c.ArgsExample
			e.SendsTraffic, e.Mutating = c.SendsTraffic, c.Mutating
		}
		out = append(out, e)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"bundle":   jsautomation.BundleVersion,
		"methods":  out,
		"storage":  storageDocs,
		"globals":  globalDocs,
		"triggers": jsautomation.Triggers,
	})
}

// ---- The run budget ----
//
// The operator's run policy, plus everything needed to explain it: the shipped default
// and ceiling per field, the unit each is entered in, and the one-sentence rationale for
// each. All of it is served rather than restated in the frontend, so what the UI explains
// cannot drift from what the runtime enforces.

type budgetResponse struct {
	// Policy is what the operator set. A zero field means "Joro's own number".
	Policy jsruntime.BudgetPolicy `json:"policy"`
	// Effective is what a run that asks for nothing is held to, EffectiveMax the most
	// one may ask for, and Host the resolved host limits. All three are what the policy
	// actually comes to, so the UI shows no figure the runtime would not honor.
	Effective    jsruntime.Budget     `json:"effective"`
	EffectiveMax jsruntime.Budget     `json:"effectiveMax"`
	Host         jsruntime.HostBudget `json:"host"`
	// Specs describes the per-run fields, hostSpecs the ones that belong to this Joro.
	Specs     []jsruntime.BudgetSpec `json:"specs"`
	HostSpecs []jsruntime.BudgetSpec `json:"hostSpecs"`
	// AgentOutputCap is the size the two agent figures share. Their own specs carry it
	// as a cap; this is here so the panel can name the sum rule once.
	AgentOutputCap int `json:"agentOutputCap"`

	// Command is the same thing for local command runs, on a separate policy with its own
	// fields; see internal/localcmd/budget.go for why the two are not one struct.
	//
	// Nested rather than flattened so the panel renders two sections from one response
	// without having to know which key belongs to which. Its specs have the same shape as
	// the ones above, which is what lets one component render both.
	Command commandBudgetResponse `json:"command"`
}

type commandBudgetResponse struct {
	// Enabled is whether --automation-commands was given. The panel still shows the
	// section when it is false — an operator can set a budget for something they have
	// not switched on yet — but says so rather than implying commands will run.
	Enabled bool `json:"enabled"`

	Policy       localcmd.Policy     `json:"policy"`
	Effective    localcmd.Budget     `json:"effective"`
	EffectiveMax localcmd.Budget     `json:"effectiveMax"`
	Host         localcmd.HostBudget `json:"host"`

	Specs     []localcmd.BudgetSpec `json:"specs"`
	HostSpecs []localcmd.BudgetSpec `json:"hostSpecs"`
}

func (s *APIServer) scriptBudgetState() budgetResponse {
	p := s.autoStore.ScriptBudget()
	def, maxi := p.Bounds()

	cp := s.autoStore.CommandBudget()
	cdef, cmaxi := cp.Bounds()

	return budgetResponse{
		Policy:         p,
		Effective:      def,
		EffectiveMax:   maxi,
		Host:           p.Host.Resolved(),
		Specs:          jsruntime.BudgetSpecs(),
		HostSpecs:      jsruntime.HostSpecs(),
		AgentOutputCap: jsruntime.AgentOutputCap,
		Command: commandBudgetResponse{
			Enabled:      s.commandsEnabled(),
			Policy:       cp,
			Effective:    cdef,
			EffectiveMax: cmaxi,
			Host:         cp.Host.Resolved(),
			Specs:        localcmd.BudgetSpecs(),
			HostSpecs:    localcmd.HostSpecs(),
		},
	}
}

func (s *APIServer) handleGetScriptBudget(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomations(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.scriptBudgetState())
}

// handleSetScriptBudget stores the operator's run policy.
//
// Over-ceiling values are rejected rather than clamped, which is the opposite of what a
// run request gets: a run may be submitted by a language model, where an argument error
// costs a turn, but this is the operator's own form and silently correcting what they
// typed would leave them believing a limit they do not have.
func (s *APIServer) handleSetScriptBudget(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomations(w) {
		return
	}
	// Both policies arrive on one request and are stored together, because the panel edits
	// them in one form and a partial save would leave the operator's two halves out of
	// step with what they were looking at. Absent means unchanged, so a client that
	// predates the command budget cannot clear one by omission.
	var body struct {
		Policy  jsruntime.BudgetPolicy `json:"policy"`
		Command *localcmd.Policy       `json:"command,omitempty"`
	}
	if err := decodeAutomationJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateBudgetPolicy(body.Policy); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Command != nil {
		if err := validateCommandPolicy(*body.Command); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := s.autoStore.SetScriptBudget(body.Policy); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if body.Command != nil {
		if err := s.autoStore.SetCommandBudget(*body.Command); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	// No WS event: nothing listens for one, the operator's own request is the only way
	// here, and it takes effect on the next run rather than on anything already open.
	writeJSON(w, http.StatusOK, s.scriptBudgetState())
}

// validateBudgetPolicy checks every field the runtime declares, in the units the
// operator entered them in, plus the one cross-field rule.
//
// Iterating the specs rather than the struct keeps this total: a field the runtime
// declares but cannot read back is reported as a defect rather than waved through.
func validateBudgetPolicy(p jsruntime.BudgetPolicy) error {
	perRun := []struct {
		what   string
		budget jsruntime.Budget
	}{
		{"default", p.Defaults},
		{"maximum", p.Maxima},
	}
	for _, sp := range jsruntime.BudgetSpecs() {
		for _, half := range perRun {
			v, ok := half.budget.Value(sp.Key)
			if !ok {
				return fmt.Errorf("budget field %q cannot be read back; this is a defect in Joro", sp.Key)
			}
			if err := checkBudgetField(scriptField(sp), v, half.what+" "); err != nil {
				return err
			}
		}
		// A default above the maximum is contradictory rather than merely high. The
		// runtime resolves it to the maximum, but saying so beats storing it.
		def, _ := p.Defaults.Value(sp.Key)
		maxi, _ := p.Maxima.Value(sp.Key)
		if def > 0 && maxi > 0 && def > maxi {
			return fmt.Errorf("%s: the default (%d) cannot be above the maximum (%d)",
				sp.Label, def/sp.Factor, maxi/sp.Factor)
		}
	}

	for _, sp := range jsruntime.HostSpecs() {
		v, ok := p.Host.Value(sp.Key)
		if !ok {
			return fmt.Errorf("host limit %q cannot be read back; this is a defect in Joro", sp.Key)
		}
		if err := checkBudgetField(scriptField(sp), v, ""); err != nil {
			return err
		}
	}

	// The pair an agent gets back has to fit inside script.run's output cap, which is
	// registered before the registry is sealed and errors rather than truncating.
	h := p.Host.Resolved()
	if room := capreg.ScriptRunOutputCap - capreg.ScriptRunHeaderRoom; h.AgentLogBytes+h.AgentResultBytes > room {
		return fmt.Errorf("agent log output (%d KB) and agent result size (%d KB) together must stay "+
			"under %d KB, the tool result cap they share",
			h.AgentLogBytes>>10, h.AgentResultBytes>>10, room>>10)
	}
	return nil
}

// validateCommandPolicy is validateBudgetPolicy for the command budget.
//
// The same shape and the same rules, over localcmd's specs. Two functions rather than one
// generic over both because the two policies have different types for their halves and
// different cross-field rules — this one has none, where the script budget has the agent
// output sum. What they do share is checkBudgetField, through budgetField.
func validateCommandPolicy(p localcmd.Policy) error {
	perRun := []struct {
		what   string
		budget localcmd.Budget
	}{
		{"default", p.Defaults},
		{"maximum", p.Maxima},
	}
	for _, sp := range localcmd.BudgetSpecs() {
		f := commandField(sp)
		for _, half := range perRun {
			v, ok := half.budget.Value(sp.Key)
			if !ok {
				return fmt.Errorf("command budget field %q cannot be read back; this is a defect in Joro",
					sp.Key)
			}
			if err := checkBudgetField(f, v, half.what+" "); err != nil {
				return err
			}
		}
		def, _ := p.Defaults.Value(sp.Key)
		maxi, _ := p.Maxima.Value(sp.Key)
		if def > 0 && maxi > 0 && def > maxi {
			return fmt.Errorf("%s: the default (%d) cannot be above the maximum (%d)",
				sp.Label, def/sp.Factor, maxi/sp.Factor)
		}
	}

	for _, sp := range localcmd.HostSpecs() {
		v, ok := p.Host.Value(sp.Key)
		if !ok {
			return fmt.Errorf("command host limit %q cannot be read back; this is a defect in Joro", sp.Key)
		}
		if err := checkBudgetField(commandField(sp), v, ""); err != nil {
			return err
		}
	}
	return nil
}

// budgetField is the subset of a budget spec the validator reads.
//
// jsruntime and localcmd each declare their own spec type with these fields in it, because
// neither imports the other and neither should. This is the one place that has to treat
// them alike, so the conversion lives here rather than either of them growing a dependency
// for a validator's convenience.
type budgetField struct {
	Label, Unit, CapReason string
	Factor, Default, Cap   int
}

func scriptField(sp jsruntime.BudgetSpec) budgetField {
	return budgetField{
		Label: sp.Label, Unit: sp.Unit, CapReason: sp.CapReason,
		Factor: sp.Factor, Default: sp.Default, Cap: sp.Cap,
	}
}

func commandField(sp localcmd.BudgetSpec) budgetField {
	return budgetField{
		Label: sp.Label, Unit: sp.Unit, CapReason: sp.CapReason,
		Factor: sp.Factor, Default: sp.Default, Cap: sp.Cap,
	}
}

// checkBudgetField reports a value the runtime cannot honor, in the operator's own unit.
//
// Only two things can be wrong: a fraction of the unit, or a value above a structural cap.
// A field with no cap has no upper bound here — the operator's number is the limit, which
// is what stops this form presenting a figure as theirs to set and then refusing it.
func checkBudgetField(sp budgetField, v int, half string) error {
	name := half + strings.ToLower(sp.Label)
	switch {
	case v < 0:
		return fmt.Errorf("%s cannot be negative; 0 takes Joro's %d %s", name, sp.Default, sp.Unit)
	case v%sp.Factor != 0:
		return fmt.Errorf("%s must be a whole number of %s", name, sp.Unit)
	case sp.Cap > 0 && v > sp.Cap*sp.Factor:
		return fmt.Errorf("%s cannot be above %d %s: %s", name, sp.Cap, sp.Unit, sp.CapReason)
	}
	return nil
}

// globalDocs covers what the shim defines outside the joro namespace. The sandbox's
// globals are ECMAScript built-ins and nothing else, so these are worth naming.
var globalDocs = []map[string]string{
	{"js": "console.log / warn / error / debug", "description": "Writes to the run log, against the run's log budget."},
	{"js": "atob(base64)", "description": "Decodes base64 to a binary string. A lens gets its bytes this way."},
	{"js": "btoa(binary)", "description": "Encodes a binary string as base64."},
}

// storageDocs describes joro.storage, which has no capability behind it to borrow a
// description from. See jsruntime.StorageBridge for why it is not one.
var storageDocs = []map[string]string{
	{"js": "joro.storage.get(key)", "description": "The value stored under key, or null. Installed automations only."},
	{"js": "joro.storage.set(key, value)", "description": "Store any JSON value under key."},
	{"js": "joro.storage.delete(key)", "description": "Remove key; returns whether it existed."},
	{"js": "joro.storage.keys()", "description": "Every key this automation has stored, sorted."},
}
