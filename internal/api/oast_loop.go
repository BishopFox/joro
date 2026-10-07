package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// StartOASTLoop launches the out-of-band confirmer and the domain refresher. Like
// the echo and tech loops it runs unconditionally and no-ops per cycle while the
// callback domain is unknown, so configuring a listener later needs no restart.
func (s *APIServer) StartOASTLoop(ctx context.Context) {
	if s.oastEngine == nil {
		return
	}
	go s.oastEngine.Run(ctx)
	go s.refreshOASTDomain(ctx)
}

// callbackDomainForOAST is the domain the confirmer harvests callback tokens
// under. Read every cycle so a domain learned from the listener takes effect live.
func (s *APIServer) callbackDomainForOAST() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oastDomain
}

// refreshOASTDomain keeps oastDomain current. A local --domain is authoritative
// and needs no fetch; otherwise, when a listener URL is configured, it fills the
// domain in from the listener's callback config on an interval. Best-effort: a
// failed or unconfigured fetch simply leaves the confirmer idle.
func (s *APIServer) refreshOASTDomain(ctx context.Context) {
	s.mu.RLock()
	local := s.cfg.CallbackDomain
	s.mu.RUnlock()
	if local != "" {
		return
	}

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	s.fetchOASTDomain(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.fetchOASTDomain(ctx)
		}
	}
}

// fetchOASTDomain reads the callback domain from the configured listener and
// caches it. No-op when no listener URL is set.
func (s *APIServer) fetchOASTDomain(ctx context.Context) {
	s.mu.RLock()
	listenerURL := s.settings.ListenerURL
	teamToken := s.settings.TeamToken
	teamNickname := s.settings.TeamNickname
	s.mu.RUnlock()
	if listenerURL == "" {
		return
	}

	url := strings.TrimRight(listenerURL, "/") + "/api/v1/callbacks/config"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	if teamToken != "" {
		req.Header.Set("Authorization", "Bearer "+teamToken)
	}
	if teamNickname != "" {
		req.Header.Set("X-Joro-Nickname", teamNickname)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var cfg struct {
		Domain string `json:"domain"`
	}
	if json.NewDecoder(resp.Body).Decode(&cfg) != nil || cfg.Domain == "" {
		return
	}
	s.mu.Lock()
	s.oastDomain = cfg.Domain
	s.mu.Unlock()
}
