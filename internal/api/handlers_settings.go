package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/proxy"
)

func (s *APIServer) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	settings := s.settings
	s.mu.RUnlock()

	if s.listenerMode {
		writeJSON(w, http.StatusOK, settings)
		return
	}

	resp := struct {
		Settings
		ScopeEnabled bool              `json:"scopeEnabled"`
		ScopeRules   []proxy.ScopeRule `json:"scopeRules"`
	}{
		Settings:     settings,
		ScopeEnabled: s.scope.IsEnabled(),
		ScopeRules:   s.scope.Rules(),
	}
	if resp.ScopeRules == nil {
		resp.ScopeRules = []proxy.ScopeRule{}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		InterceptEnabled *bool   `json:"interceptEnabled"`
		InterceptTimeout *int    `json:"interceptTimeout"`
		ListenerURL      *string `json:"listenerUrl"`
		HTTP2Enabled     *bool   `json:"http2Enabled"`
		KeepAliveEnabled *bool   `json:"keepAliveEnabled"`
		SOCKSHost        *string `json:"socksHost"`
		SOCKSPort        *int    `json:"socksPort"`
		SOCKSUsername    *string `json:"socksUsername"`
		SOCKSPassword    *string `json:"socksPassword"`
		SOCKSDNS         *bool   `json:"socksDns"`
		TeamToken           *string `json:"teamToken"`
		TeamNickname        *string `json:"teamNickname"`
		MaxRequests         *int    `json:"maxRequests"`
		DisableUpdateChecks *bool   `json:"disableUpdateChecks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.mu.Lock()
	if body.InterceptEnabled != nil && s.intercept != nil {
		s.settings.InterceptEnabled = *body.InterceptEnabled
		s.intercept.SetEnabled(*body.InterceptEnabled)
	}
	if body.InterceptTimeout != nil && *body.InterceptTimeout > 0 && s.intercept != nil {
		s.settings.InterceptTimeout = *body.InterceptTimeout
		s.intercept.SetTimeout(time.Duration(*body.InterceptTimeout) * time.Second)
	}
	oldURL := s.settings.ListenerURL
	oldToken := s.settings.TeamToken
	oldNick := s.settings.TeamNickname
	urlChanged := false
	tokenChanged := false
	nickChanged := false

	if body.ListenerURL != nil {
		s.settings.ListenerURL = *body.ListenerURL
		urlChanged = *body.ListenerURL != oldURL
	}
	if body.HTTP2Enabled != nil && s.transport != nil {
		s.settings.HTTP2Enabled = *body.HTTP2Enabled
		s.transport.SetHTTP2(*body.HTTP2Enabled)
	}
	if body.KeepAliveEnabled != nil && s.transport != nil {
		s.settings.KeepAliveEnabled = *body.KeepAliveEnabled
		s.transport.SetKeepAlive(*body.KeepAliveEnabled)
	}

	socksChanged := false
	if body.SOCKSHost != nil {
		s.settings.SOCKSHost = *body.SOCKSHost
		socksChanged = true
	}
	if body.SOCKSPort != nil {
		s.settings.SOCKSPort = *body.SOCKSPort
		socksChanged = true
	}
	if body.SOCKSUsername != nil {
		s.settings.SOCKSUsername = *body.SOCKSUsername
		socksChanged = true
	}
	if body.SOCKSPassword != nil {
		s.settings.SOCKSPassword = *body.SOCKSPassword
		socksChanged = true
	}
	if body.SOCKSDNS != nil {
		s.settings.SOCKSDNS = *body.SOCKSDNS
		socksChanged = true
	}
	if socksChanged && s.transport != nil {
		s.transport.SetSOCKS(
			s.settings.SOCKSHost,
			s.settings.SOCKSPort,
			s.settings.SOCKSUsername,
			s.settings.SOCKSPassword,
			s.settings.SOCKSDNS,
		)
	}

	if body.TeamToken != nil {
		s.settings.TeamToken = *body.TeamToken
		tokenChanged = *body.TeamToken != oldToken
	}
	if body.TeamNickname != nil {
		s.settings.TeamNickname = *body.TeamNickname
		nickChanged = *body.TeamNickname != oldNick
	}
	if body.MaxRequests != nil && *body.MaxRequests > 0 && s.store != nil {
		s.settings.MaxRequests = *body.MaxRequests
		s.store.SetMaxSize(*body.MaxRequests)
	}
	if body.DisableUpdateChecks != nil {
		s.settings.DisableUpdateChecks = *body.DisableUpdateChecks
	}

	settings := s.settings
	s.mu.Unlock()

	teamSettingsChanged := urlChanged || tokenChanged || nickChanged

	if s.listenerRelay != nil && teamSettingsChanged {
		nickOnly := nickChanged && !urlChanged && !tokenChanged
		canRename := nickOnly &&
			settings.TeamNickname != "" &&
			settings.ListenerURL != "" &&
			settings.TeamToken != ""

		if canRename {
			if err := s.renameOnTeamServer(settings.ListenerURL, settings.TeamToken, oldNick, settings.TeamNickname); err != nil {
				if errors.Is(err, errNicknameInUse) {
					s.mu.Lock()
					s.settings.TeamNickname = oldNick
					s.mu.Unlock()
					writeError(w, http.StatusConflict, err.Error())
					return
				}
				// Not connected / transport failure: fall back to reconnect.
				s.listenerRelay.Update(settings.ListenerURL, settings.TeamToken, settings.TeamNickname)
			} else {
				s.listenerRelay.SetNickname(settings.TeamNickname)
			}
		} else {
			s.listenerRelay.Update(settings.ListenerURL, settings.TeamToken, settings.TeamNickname)
		}
	}

	writeJSON(w, http.StatusOK, settings)
}

// renameOnTeamServer returns nil on success, errNicknameInUse on 409, or an error otherwise.
func (s *APIServer) renameOnTeamServer(listenerURL, token, oldNick, newNick string) error {
	bodyJSON, err := json.Marshal(map[string]string{
		"oldNickname": oldNick,
		"newNickname": newNick,
	})
	if err != nil {
		return err
	}

	base := strings.TrimRight(listenerURL, "/")
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/team/nickname", bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Joro-Nickname", oldNick)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return errNicknameInUse
	default:
		return fmt.Errorf("teamserver returned %d", resp.StatusCode)
	}
}
