package api

import (
	"net"
	"net/http"
	"os"
	"time"

	"github.com/BishopFox/joro/internal/browser"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/update"
)

func (s *APIServer) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()

	ip := "127.0.0.1"
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				ip = ipNet.IP.String()
				break
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"hostname": hostname,
		"ip":       ip,
	})
}

// handleHealthCheck reports the state the first-run wizard polls: proxy/UI
// addressing, CA presence, whether a launchable browser is installed, and the
// number of captured requests (used to confirm live traffic is flowing).
func (s *APIServer) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	_, browserName, browserAvailable := browser.Find()

	s.mu.RLock()
	activeProject := s.activeProjectConfig
	s.mu.RUnlock()

	requestCount := 0
	if s.store != nil {
		requestCount = s.store.Count()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"proxyPort":        s.cfg.ProxyPort,
		"uiPort":           s.cfg.UIPort,
		"bindAddr":         s.cfg.BindAddr,
		"caPresent":        s.ca != nil,
		"browserAvailable": browserAvailable,
		"browserName":      browserName,
		"requestCount":     requestCount,
		"activeProject":    activeProject,
	})
}

func (s *APIServer) handleVersionInfo(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	info := s.buildInfo
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, info)
}

// handleCheckUpdate runs an on-demand update check and refreshes BuildInfo.
// Runs regardless of the DisableUpdateChecks setting — it is an explicit user
// action, not an automatic check. Does NOT perform the update itself; the
// UpdateBanner component owns the save-configs-and-update flow.
func (s *APIServer) handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	currentVersion := s.buildInfo.Version
	prevAvailable := s.buildInfo.UpdateAvailable
	prevLatest := s.buildInfo.LatestVersion
	s.mu.RUnlock()

	latestVersion, available := update.CheckForUpdate(currentVersion)

	s.mu.Lock()
	s.buildInfo.UpdateAvailable = available
	s.buildInfo.LatestVersion = latestVersion
	info := s.buildInfo
	s.mu.Unlock()

	if available && (!prevAvailable || prevLatest != latestVersion) {
		s.hub.Broadcast() <- event.WSEvent{
			Type: "system.update.available",
			Data: info,
		}
	}

	writeJSON(w, http.StatusOK, info)
}

func (s *APIServer) handleRestart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})

	go func() {
		s.hub.Broadcast() <- event.WSEvent{
			Type: "system.update.restarting",
			Data: map[string]string{},
		}

		// Give the WebSocket event time to reach clients before shutting down.
		time.Sleep(500 * time.Millisecond)

		s.restart = true
		if s.cancelFunc != nil {
			s.cancelFunc()
		}
	}()
}

func (s *APIServer) handleUpdate(w http.ResponseWriter, r *http.Request) {
	// Respond immediately; the update runs in the background with progress via WebSocket.
	// RunUpdate detects install mode internally — git checkouts run `git pull && make build`,
	// downloaded binaries fetch the matching goreleaser asset from GitHub.
	writeJSON(w, http.StatusOK, map[string]string{"status": "updating"})

	go func() {
		progress := func(msg string) {
			s.hub.Broadcast() <- event.WSEvent{
				Type: "system.update.progress",
				Data: map[string]string{"stage": msg},
			}
		}

		if err := update.RunUpdate(progress); err != nil {
			s.hub.Broadcast() <- event.WSEvent{
				Type: "system.update.failed",
				Data: map[string]string{"error": err.Error()},
			}
			return
		}

		s.hub.Broadcast() <- event.WSEvent{
			Type: "system.update.restarting",
			Data: map[string]string{},
		}

		// Give the WebSocket event time to reach clients before shutting down.
		time.Sleep(500 * time.Millisecond)

		// Trigger graceful shutdown; main.go will call update.Restart() after Start() returns.
		s.restart = true
		if s.cancelFunc != nil {
			s.cancelFunc()
		}
	}()
}
