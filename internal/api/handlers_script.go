package api

import (
	"net/http"
	"strconv"
)

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
