package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/automation"
	"github.com/BishopFox/joro/internal/capability"
)

// The automation control plane. These routes exist only in proxy mode, only when
// a token store was configured, and only behind originGuard — the same same-origin
// gate the rest of the UI API uses.
//
// They are deliberately not capabilities and never will be. An automation client
// reaches Joro on a different port, on a mux where /api/v1/* is not registered at
// all, so there is no route from a bearer token to this file. See
// internal/capability/reserved.go for the full argument.

// tokenView is the API shape of a token. It has no secret field, and neither does
// automation.Token — the plaintext exists only in the create and rotate replies.
type tokenView struct {
	automation.Token
	// UngrantedCapabilities is the set difference against the live registry, so
	// the UI can say "three new capabilities exist" without ever granting one.
	UngrantedCapabilities []string `json:"ungrantedCapabilities,omitempty"`
	// SendsTraffic drives the UI's warning affordances.
	SendsTraffic bool `json:"sendsTraffic"`
	Expired      bool `json:"expired"`
}

type capabilityView struct {
	ID             string          `json:"id"`
	Class          string          `json:"class"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	Mutating       bool            `json:"mutating"`
	SendsTraffic   bool            `json:"sendsTraffic"`
	InputSchema    json.RawMessage `json:"inputSchema"`
	MaxOutputBytes int             `json:"maxOutputBytes"`
	ToolName       string          `json:"toolName"`
}

func (s *APIServer) requireAutomation(w http.ResponseWriter) bool {
	if !s.automationEnabled() {
		writeError(w, http.StatusNotFound, "automation is not enabled on this instance")
		return false
	}
	return true
}

func (s *APIServer) handleListAutomationTokens(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": s.tokenViews()})
}

func (s *APIServer) tokenViews() []tokenView {
	tokens := s.autoStore.List()
	registered := s.capRegistry.IDs()
	now := time.Now()

	out := make([]tokenView, 0, len(tokens))
	for i := range tokens {
		t := tokens[i]
		held := make(map[string]struct{}, len(t.Grants))
		for _, g := range t.Grants {
			held[g] = struct{}{}
		}
		var ungranted []string
		for _, id := range registered {
			if _, ok := held[id]; !ok {
				ungranted = append(ungranted, id)
			}
		}
		out = append(out, tokenView{
			Token:                 t,
			UngrantedCapabilities: ungranted,
			SendsTraffic:          t.SendsTraffic(s.capRegistry),
			Expired:               t.Expired(now),
		})
	}
	return out
}

type createTokenReq struct {
	Name            string   `json:"name"`
	Grants          []string `json:"grants"`
	RequireScope    *bool    `json:"requireScope"`
	HostAllow       []string `json:"hostAllow"`
	RateLimitPerMin int      `json:"rateLimitPerMin"`
	MaxConcurrent   int      `json:"maxConcurrent"`
	MaxOutputBytes  int      `json:"maxOutputBytes"`
	ExpiresInDays   int      `json:"expiresInDays"`
}

func (s *APIServer) handleCreateAutomationToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	var body createTokenReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.validateTokenInput(body.Name, body.Grants, body.HostAllow,
		body.RateLimitPerMin, body.MaxConcurrent, body.MaxOutputBytes, body.ExpiresInDays); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Default requireScope to on. A token that can send is far more dangerous
	// than one that cannot, and the safe default should not depend on the client
	// remembering to ask for it.
	requireScope := true
	if body.RequireScope != nil {
		requireScope = *body.RequireScope
	}

	tok, secret, err := s.autoStore.Create(automation.CreateParams{
		Name:             body.Name,
		Grants:           normalizeGrants(body.Grants),
		RequireScope:     requireScope,
		HostAllow:        normalizeHostAllow(body.HostAllow),
		RateLimitPerMin:  body.RateLimitPerMin,
		MaxConcurrent:    body.MaxConcurrent,
		MaxOutputBytes:   body.MaxOutputBytes,
		ExpiresInDays:    body.ExpiresInDays,
		CapsFingerprint:  s.capRegistry.Fingerprint(),
		GrantedAtVersion: s.buildInfo.Version,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The only response in the whole API that carries a plaintext secret.
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "secret": secret})
}

type updateTokenReq struct {
	Name            *string   `json:"name"`
	Grants          *[]string `json:"grants"`
	RequireScope    *bool     `json:"requireScope"`
	HostAllow       *[]string `json:"hostAllow"`
	RateLimitPerMin *int      `json:"rateLimitPerMin"`
	MaxConcurrent   *int      `json:"maxConcurrent"`
	MaxOutputBytes  *int      `json:"maxOutputBytes"`
}

func (s *APIServer) handleUpdateAutomationToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	var body updateTokenReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	p := automation.UpdateParams{
		Name: body.Name, RequireScope: body.RequireScope,
		RateLimitPerMin: body.RateLimitPerMin, MaxConcurrent: body.MaxConcurrent,
		MaxOutputBytes: body.MaxOutputBytes,
	}
	if body.Grants != nil {
		if err := s.validateGrants(*body.Grants); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		g := normalizeGrants(*body.Grants)
		p.Grants = &g
		// Editing grants is a review, so stamp the current fingerprint.
		fp := s.capRegistry.Fingerprint()
		p.CapsFingerprint = &fp
		v := s.buildInfo.Version
		p.GrantedAtVersion = &v
	}
	if body.HostAllow != nil {
		if err := validateHostAllow(*body.HostAllow); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h := normalizeHostAllow(*body.HostAllow)
		p.HostAllow = &h
	}
	if body.RateLimitPerMin != nil || body.MaxConcurrent != nil || body.MaxOutputBytes != nil {
		if err := validateLimits(deref(body.RateLimitPerMin), deref(body.MaxConcurrent), deref(body.MaxOutputBytes)); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	tok, err := s.autoStore.Update(r.PathValue("id"), p)
	if err != nil {
		s.writeTokenErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok})
}

func (s *APIServer) handleRotateAutomationToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	tok, secret, err := s.autoStore.Rotate(r.PathValue("id"))
	if err != nil {
		s.writeTokenErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "secret": secret})
}

func (s *APIServer) handleSetAutomationTokenEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	disabled := !body.Enabled
	tok, err := s.autoStore.Update(r.PathValue("id"), automation.UpdateParams{Disabled: &disabled})
	if err != nil {
		s.writeTokenErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok})
}

// handleReviewAutomationToken stamps the current capability fingerprint without
// touching grants, which is how an operator dismisses the "new capabilities
// available" badge deliberately rather than by accident.
func (s *APIServer) handleReviewAutomationToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	fp := s.capRegistry.Fingerprint()
	v := s.buildInfo.Version
	tok, err := s.autoStore.Update(r.PathValue("id"), automation.UpdateParams{
		CapsFingerprint: &fp, GrantedAtVersion: &v,
	})
	if err != nil {
		s.writeTokenErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok})
}

func (s *APIServer) handleRevokeAutomationToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.autoStore.Revoke(id); err != nil {
		s.writeTokenErr(w, err)
		return
	}
	// Drop the limiter state so a future token cannot inherit a drained bucket.
	s.capRegistry.Forget(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *APIServer) handleListCapabilities(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	caps := s.capRegistry.All()
	out := make([]capabilityView, 0, len(caps))
	for _, c := range caps {
		out = append(out, capabilityView{
			ID: c.ID, Class: string(c.Class), Title: c.Title, Description: c.Description,
			Mutating: c.Mutating, SendsTraffic: c.SendsTraffic,
			InputSchema:    c.InputSchema,
			MaxOutputBytes: c.MaxOutputBytes,
			ToolName:       strings.ReplaceAll(c.ID, ".", "_"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"capabilities": out,
		"fingerprint":  s.capRegistry.Fingerprint(),
		"classes":      capability.Classes,
	})
}

func (s *APIServer) handleListAutomationAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 1000)

	entries, total := s.capAudit.List(capability.AuditFilter{
		TokenID:    q.Get("tokenId"),
		Capability: q.Get("capability"),
		Result:     q.Get("result"),
		Offset:     offset,
		Limit:      limit,
	})
	// The dashboard widget wants counts, not rows; computing them here saves it a
	// second request and keeps the window definition in one place.
	total1h, denied1h, errors1h := s.capAudit.Stats(time.Now().Add(-time.Hour))

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
		"stats": map[string]int{
			"lastHour":       total1h,
			"deniedLastHour": denied1h,
			"errorsLastHour": errors1h,
			"tokens":         s.autoStore.Count(),
			"tokensActive":   s.activeTokenCount(),
		},
	})
}

func (s *APIServer) activeTokenCount() int {
	now := time.Now()
	n := 0
	for _, t := range s.autoStore.List() {
		if t.Usable(now) {
			n++
		}
	}
	return n
}

func (s *APIServer) handleClearAutomationAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": s.capAudit.Clear()})
}

func (s *APIServer) handleGetMCPState(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.mcpState())
}

func (s *APIServer) handleSetMCPState(w http.ResponseWriter, r *http.Request) {
	if !s.requireAutomation(w) {
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
		Port    *int  `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Serialize start/stop: two concurrent PUTs could otherwise both see "not
	// running" and race the bind.
	s.automationMu.Lock()
	defer s.automationMu.Unlock()

	state := s.autoStore.MCP()
	if body.Port != nil {
		if *body.Port < 1 || *body.Port > 65535 {
			writeError(w, http.StatusBadRequest, "port must be between 1 and 65535")
			return
		}
		if *body.Port == s.cfg.UIPort || *body.Port == s.cfg.ProxyPort {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("port %d is already used by Joro's UI or proxy", *body.Port))
			return
		}
		state.Port = *body.Port
	}
	if body.Enabled != nil {
		state.Enabled = *body.Enabled
	}

	// Always stop first: this makes a port change a single atomic action from the
	// operator's point of view rather than a stop they have to remember.
	if err := s.stopMCPListener(); err != nil {
		writeError(w, http.StatusInternalServerError, "stopping the MCP listener: "+err.Error())
		return
	}
	if state.Enabled {
		if err := s.startMCPListener(state.Port); err != nil {
			// Do not persist Enabled when the bind failed — the UI would then
			// show "enabled" with nothing listening, and a restart would retry
			// a port the operator never saw fail.
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}
	if err := s.autoStore.SetMCP(state); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.mcpState())
}

// ---- validation. The UI is not a control; everything it can send is checked here.

func (s *APIServer) validateTokenInput(name string, grants, hostAllow []string, rate, conc, out, days int) error {
	if n := strings.TrimSpace(name); n == "" || len(n) > automation.MaxNameLen {
		return fmt.Errorf("name must be 1-%d characters", automation.MaxNameLen)
	}
	if err := s.validateGrants(grants); err != nil {
		return err
	}
	if err := validateHostAllow(hostAllow); err != nil {
		return err
	}
	if err := validateLimits(rate, conc, out); err != nil {
		return err
	}
	if days < 0 || days > automation.MaxExpiryDays {
		return fmt.Errorf("expiresInDays must be between 0 and %d", automation.MaxExpiryDays)
	}
	return nil
}

// validateGrants rejects unknown and reserved capability IDs.
//
// The reserved check is redundant with the registry's own — a reserved ID cannot
// be registered, so it would already fail the unknown check — but it produces a
// message that explains the policy rather than one that says "unknown", which is
// what an operator hand-crafting a request needs to read.
func (s *APIServer) validateGrants(grants []string) error {
	var unknown, reserved []string
	known := make(map[string]struct{})
	for _, id := range s.capRegistry.IDs() {
		known[id] = struct{}{}
	}
	for _, g := range grants {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if capability.IsReserved(g) {
			reserved = append(reserved, g)
			continue
		}
		if _, ok := known[g]; !ok {
			unknown = append(unknown, g)
		}
	}
	if len(reserved) > 0 {
		return fmt.Errorf("these grants are in reserved namespaces and can never be granted: %s. "+
			"Token and grant management is available only in this interface", strings.Join(reserved, ", "))
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown capabilities: %s", strings.Join(unknown, ", "))
	}
	return nil
}

func validateHostAllow(patterns []string) error {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// filepath.Match only reports a bad pattern when it actually parses one,
		// so match against a throwaway string to surface ErrBadPattern.
		if _, err := filepath.Match(p, "example.com"); err != nil {
			return fmt.Errorf("invalid host pattern %q: %v", p, err)
		}
	}
	return nil
}

func validateLimits(rate, conc, out int) error {
	if rate != 0 && (rate < automation.MinRateLimitPerMin || rate > automation.MaxRateLimitPerMin) {
		return fmt.Errorf("rateLimitPerMin must be between %d and %d",
			automation.MinRateLimitPerMin, automation.MaxRateLimitPerMin)
	}
	if conc != 0 && (conc < automation.MinMaxConcurrent || conc > automation.MaxMaxConcurrent) {
		return fmt.Errorf("maxConcurrent must be between %d and %d",
			automation.MinMaxConcurrent, automation.MaxMaxConcurrent)
	}
	if out != 0 && (out < automation.MinOutputBytes || out > automation.MaxOutputBytes) {
		return fmt.Errorf("maxOutputBytes must be between %d and %d",
			automation.MinOutputBytes, automation.MaxOutputBytes)
	}
	return nil
}

func normalizeGrants(grants []string) []string {
	seen := make(map[string]struct{}, len(grants))
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		g = strings.TrimSpace(g)
		if g == "" || capability.IsReserved(g) {
			continue
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func normalizeHostAllow(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *APIServer) writeTokenErr(w http.ResponseWriter, err error) {
	if errors.Is(err, automation.ErrNotFound) {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
