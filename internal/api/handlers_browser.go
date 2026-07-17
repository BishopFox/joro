package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/BishopFox/joro/internal/browser"
)

func (s *APIServer) handleBrowserStatus(w http.ResponseWriter, r *http.Request) {
	_, name, ok := browser.Find()
	writeJSON(w, http.StatusOK, map[string]any{
		"available": ok,
		"browser":   name,
	})
}

func (s *APIServer) handleBrowserLaunch(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		writeError(w, http.StatusBadRequest, "CA not initialised")
		return
	}

	var body struct {
		URL string `json:"url"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
	}

	path, name, ok := browser.Find()
	if !ok {
		writeError(w, http.StatusBadRequest, "no supported browser found")
		return
	}

	key, profileDir, ephemeral := s.browserProfile()

	host := s.cfg.BindAddr
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}

	err := browser.Launch(browser.LaunchOptions{
		BrowserPath:     path,
		ProxyAddr:       fmt.Sprintf("%s:%d", host, s.cfg.ProxyPort),
		SPKIFingerprint: browser.SPKIFingerprint(s.ca.Cert),
		ProfileDir:      profileDir,
		URL:             body.URL,
		WipeOnExit:      ephemeral,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to launch browser: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "launched",
		"browser": name,
		"profile": key,
	})
}

// handleClearBrowserCookies removes the cookie databases from the current
// project's testing-browser profile only (not the operator's own browser).
func (s *APIServer) handleClearBrowserCookies(w http.ResponseWriter, r *http.Request) {
	key, profileDir, _ := s.browserProfile()
	if err := browser.ClearCookies(profileDir); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to clear cookies: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "cleared",
		"profile": key,
	})
}

// browserProfile returns the sanitized profile key, its directory, and whether
// the profile is ephemeral for the active project. State never carries across
// projects; with no project loaded the profile is "default" and ephemeral (the
// caller wipes it when the browser closes).
func (s *APIServer) browserProfile() (key, dir string, ephemeral bool) {
	s.mu.RLock()
	active := s.activeProjectConfig
	s.mu.RUnlock()
	ephemeral = active == ""
	key = active
	if key == "" {
		key = "default"
	}
	key = sanitizeProfileKey(key)
	return key, filepath.Join(s.cfg.DataDir, "browser-profiles", key), ephemeral
}

// sanitizeProfileKey maps a project name to a filesystem-safe directory name.
func sanitizeProfileKey(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "default"
	}
	return string(out)
}
