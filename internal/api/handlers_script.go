package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/jsautomation"
	"github.com/BishopFox/joro/internal/jsruntime"
)

// maxAutomationBody bounds a request on the automation control plane. Sized for the
// largest of them — one carrying automation source — comfortably over
// jsruntime.MaxSourceBytes so the source limit is the one that reports, with room for a
// manifest beside it.
const maxAutomationBody = 2 << 20

// decodeJSON reads a bounded JSON body, and requires the JSON content type.
//
// Requiring it is deliberate rather than pedantic. `application/json` is not a
// CORS-safelisted content type, so a browser cannot send one cross-origin without a
// preflight, and a preflight against this API fails — it sets no CORS headers. That holds
// independently of originGuard, which is the primary control here but reasons from
// headers the browser volunteers: a client that sends none at all is treated as local
// tooling and allowed through. This check still applies to it, at the cost of one
// `-H 'Content-Type: application/json'`.
func decodeJSON(r *http.Request, dst any) error {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" {
		return errors.New("expected Content-Type: application/json")
	}
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxAutomationBody)).Decode(dst)
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

// requireScripting reports whether the script runner is available, writing the JSON 404
// if not. Separate from requireAutomation: automation can be on while scripting is off,
// and "automation is not enabled" would send an operator looking in the wrong place.
func (s *APIServer) requireScripting(w http.ResponseWriter) bool {
	if !s.requireAutomation(w) {
		return false
	}
	if s.scriptManager == nil {
		writeError(w, http.StatusNotFound,
			"script automation is not enabled on this instance; start Joro with --automation-scripting")
		return false
	}
	return true
}

func (s *APIServer) handleListScriptRuns(w http.ResponseWriter, r *http.Request) {
	if !s.requireScripting(w) {
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
	if !s.requireScripting(w) {
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
	if !s.requireScripting(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": s.scriptManager.Runs().Clear()})
}

// ---- Installed automations ----

// packages returns the installed-automation store, writing the 404 if unavailable.
func (s *APIServer) packages(w http.ResponseWriter) *jsautomation.Store {
	if !s.requireScripting(w) {
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
	writeJSON(w, http.StatusOK, a)
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
	if err := decodeJSON(r, &body); err != nil {
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
	if err := decodeJSON(r, &body); err != nil {
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
	if err := decodeJSON(r, &body); err != nil {
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
	if err := decodeJSON(r, &body); err != nil {
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
	if !s.requireScripting(w) {
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
	if err := decodeJSON(r, &body); err != nil {
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
		run, err = s.scriptManager.Run(r.Context(), jsautomation.RunRequest{
			Source:  body.Source,
			Input:   body.Input,
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
	case errors.Is(err, jsautomation.ErrBusy):
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
