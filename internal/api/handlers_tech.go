package api

import (
	"net/http"

	"github.com/BishopFox/joro/internal/techfp"
)

// techStore returns the fingerprint store, or nil when fingerprinting is not
// wired (listener/team-server mode). The active-scan rule reads it to gate checks.
func (s *APIServer) techStore() *techfp.Store {
	if s.techEngine == nil {
		return nil
	}
	return s.techEngine.Store()
}

// techAvailable rejects requests when fingerprinting is not wired, as in listener
// and team-server mode. The routes are also behind the proxy-mode gate in
// registerRoutes.
func (s *APIServer) techAvailable(w http.ResponseWriter) bool {
	if s.techEngine == nil {
		writeError(w, http.StatusNotFound, "technology fingerprinting is unavailable in this mode")
		return false
	}
	return true
}

// handleListTechHosts returns every fingerprinted host and the summary counts.
func (s *APIServer) handleListTechHosts(w http.ResponseWriter, r *http.Request) {
	if !s.techAvailable(w) {
		return
	}
	hosts, techs := s.techEngine.Store().Summary()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.techEngine.Enabled(),
		"hosts":   s.techEngine.Store().Hosts(),
		"summary": map[string]int{"hosts": hosts, "techs": techs},
		"scan":    s.techEngine.Status(),
	})
}

// handleStartTechScan re-fingerprints captured history (all hosts, or one when
// scope is "host"). Backfills a loaded project's hosts, which the live cursor skips.
func (s *APIServer) handleStartTechScan(w http.ResponseWriter, r *http.Request) {
	if !s.techAvailable(w) {
		return
	}
	var req techfp.RescanRequest
	if err := decodeJSONOptional(r, &req, maxJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	status, err := s.techEngine.StartRescan(s.detectBackgroundCtx(), req)
	if err == techfp.ErrScanRunning {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// handleGetTechScan returns the current rescan status.
func (s *APIServer) handleGetTechScan(w http.ResponseWriter, r *http.Request) {
	if !s.techAvailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.techEngine.Status())
}

// handleCancelTechScan stops a running rescan.
func (s *APIServer) handleCancelTechScan(w http.ResponseWriter, r *http.Request) {
	if !s.techAvailable(w) {
		return
	}
	s.techEngine.Cancel()
	writeJSON(w, http.StatusOK, s.techEngine.Status())
}

// handleGetTechHost returns one host's technology set.
func (s *APIServer) handleGetTechHost(w http.ResponseWriter, r *http.Request) {
	if !s.techAvailable(w) {
		return
	}
	ht, ok := s.techEngine.Store().Host(r.PathValue("host"))
	if !ok {
		writeError(w, http.StatusNotFound, "no technologies recorded for this host")
		return
	}
	writeJSON(w, http.StatusOK, ht)
}

// handleSetTechEnabled toggles passive fingerprinting.
func (s *APIServer) handleSetTechEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.techAvailable(w) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.techEngine.SetEnabled(body.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": body.Enabled})
}
