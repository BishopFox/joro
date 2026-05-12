package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/callback"
)

// proxyToListener forwards a request to the remote listener and copies the response back.
// Returns true if the response was handled (either forwarded or errored).
func (s *APIServer) proxyToListener(w http.ResponseWriter, r *http.Request) bool {
	s.mu.RLock()
	listenerURL := s.settings.ListenerURL
	s.mu.RUnlock()

	if listenerURL == "" {
		writeError(w, http.StatusServiceUnavailable, "Listener URL not configured - set it in the Interact tab")
		return true
	}

	// Strip trailing slash from base URL.
	base := strings.TrimRight(listenerURL, "/")
	targetURL := base + r.URL.RequestURI()

	client := &http.Client{Timeout: 10 * time.Second}
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create request: %v", err))
		return true
	}
	proxyReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	// Include team auth headers when forwarding to a teamserver.
	s.mu.RLock()
	teamToken := s.settings.TeamToken
	teamNickname := s.settings.TeamNickname
	s.mu.RUnlock()
	if teamToken != "" {
		proxyReq.Header.Set("Authorization", "Bearer "+teamToken)
	}
	if teamNickname != "" {
		proxyReq.Header.Set("X-Joro-Nickname", teamNickname)
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("listener unreachable: %v", err))
		return true
	}
	defer resp.Body.Close()

	// Copy response headers and body back.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
	return true
}

func (s *APIServer) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	tokens, err := s.cbStore.ListTokens()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tokens == nil {
		tokens = []callback.Token{}
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *APIServer) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	token, err := callback.GenerateToken(s.cbStore, body.Note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, token)
}

func (s *APIServer) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	id := r.PathValue("id")
	if err := s.cbStore.DeleteToken(id); err != nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *APIServer) handleListInteractions(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	tokenID := r.URL.Query().Get("token_id")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	items, total, err := s.cbStore.ListInteractions(tokenID, offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []callback.Interaction{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleClearInteractions(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	tokenID := r.URL.Query().Get("token_id")
	if err := s.cbStore.ClearInteractions(tokenID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (s *APIServer) handleGetCallbackConfig(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	cfg, err := s.cbStore.GetConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *APIServer) handleUpdateCallbackConfig(w http.ResponseWriter, r *http.Request) {
	if !s.listenerMode {
		s.proxyToListener(w, r)
		return
	}
	var cfg callback.CallbackConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.cbStore.SetConfig(&cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}
func (s *APIServer) handleGetMode(w http.ResponseWriter, r *http.Request) {
	mode := "proxy"
	if s.teamServerMode {
		mode = "teamserver"
	} else if s.listenerMode {
		mode = "listener"
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": mode, "sessionId": s.sessionID})
}
