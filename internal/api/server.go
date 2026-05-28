package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/callback"
	"github.com/BishopFox/joro/internal/cert"
	"github.com/BishopFox/joro/internal/config"
	"github.com/BishopFox/joro/internal/configstore"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/plugins"
	"github.com/BishopFox/joro/internal/fuzzer"
	"github.com/BishopFox/joro/internal/notes"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/sliver"
	"github.com/BishopFox/joro/internal/team"
	"github.com/BishopFox/joro/internal/update"
	"github.com/BishopFox/joro/internal/xsshunter"
	joroweb "github.com/BishopFox/joro/web"
)

// Settings holds runtime-adjustable configuration exposed via the API.
type Settings struct {
	ProxyPort        int    `json:"proxyPort"`
	UIPort           int    `json:"uiPort"`
	InterceptEnabled bool   `json:"interceptEnabled"`
	InterceptTimeout int    `json:"interceptTimeout"` // seconds
	ListenerURL      string `json:"listenerUrl"`
	HTTP2Enabled     bool   `json:"http2Enabled"`
	KeepAliveEnabled bool   `json:"keepAliveEnabled"`
	SOCKSHost        string `json:"socksHost"`
	SOCKSPort        int    `json:"socksPort"`
	SOCKSUsername    string `json:"socksUsername"`
	SOCKSPassword    string `json:"socksPassword"`
	SOCKSDNS         bool   `json:"socksDns"`
	TeamToken           string `json:"teamToken"`
	TeamNickname        string `json:"teamNickname"`
	MaxRequests         int    `json:"maxRequests"`
	DisableUpdateChecks bool   `json:"disableUpdateChecks"`
}

// BuildInfo holds version information embedded at build time.
type BuildInfo struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	UpdateAvailable bool   `json:"updateAvailable"`
	LatestVersion   string `json:"latestVersion"`
}

// APIServer serves the REST API and the embedded frontend.
type APIServer struct {
	cfg        config.Config
	store      *proxy.Store
	intercept  *proxy.InterceptQueue
	scope      *proxy.Scope
	noise      *proxy.NoiseFilter
	replace    *proxy.MatchReplace
	customData *proxy.CustomData
	ca         *cert.CA
	hub        *Hub

	transport    *proxy.TransportConfig
	wsStore      *proxy.WSStore
	wsManipulate *proxy.ManipulateWSManager
	cbStore      *callback.Store
	xssStore     *xsshunter.Store
	noteStore    *notes.Store
	sliverClient   *sliver.Client
	listenerMode   bool
	teamServerMode bool
	teamStore      *team.Store
	teamToken      string

	fuzzerStore   *fuzzer.Store
	pluginManager *plugins.Manager

	listenerRelay *ListenerRelay
	configStore   *configstore.Store

	buildInfo  BuildInfo
	cancelFunc context.CancelFunc
	restart    bool

	sessionID string

	highlights map[string]string // requestID → highlight color name

	mu                  sync.RWMutex
	settings            Settings
	activeUserConfig    string
	activeProjectConfig string

	// pendingUserPluginStates / pendingProjectPluginStates preserve plugin
	// state blobs across a load -> save round-trip even when the owning
	// plugin isn't installed on this machine. Populated on config load
	// (full decoded map), merged into the serialized map on config save
	// so unknown-to-us plugins' data is never dropped.
	pendingUserPluginStates    map[string][]byte
	pendingProjectPluginStates map[string][]byte

	srv *http.Server
}

// generateSessionID returns a random 16-char hex string unique to this process.
func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// New creates an APIServer.
func New(
	cfg config.Config,
	store *proxy.Store,
	intercept *proxy.InterceptQueue,
	scope *proxy.Scope,
	noise *proxy.NoiseFilter,
	replace *proxy.MatchReplace,
	customData *proxy.CustomData,
	transport *proxy.TransportConfig,
	wsStore *proxy.WSStore,
	ca *cert.CA,
	hub *Hub,
	noteStore *notes.Store,
	pluginManager *plugins.Manager,
	buildInfo BuildInfo,
	cancelFunc context.CancelFunc,
) *APIServer {
	sc := &sliver.Client{}
	sc.SetOnEvent(func(ev sliver.SliverEvent) {
		hub.Broadcast() <- event.WSEvent{Type: "sliver.event", Data: ev}
	})
	return &APIServer{
		cfg:           cfg,
		store:         store,
		intercept:     intercept,
		scope:         scope,
		noise:         noise,
		replace:       replace,
		customData:    customData,
		transport:     transport,
		wsStore:       wsStore,
		wsManipulate:  proxy.NewManipulateWSManager(transport),
		ca:            ca,
		hub:           hub,
		noteStore:     noteStore,
		sliverClient:  sc,
		fuzzerStore:   fuzzer.NewStore(),
		pluginManager: pluginManager,
		listenerRelay: NewListenerRelay(hub),
		configStore:   configstore.NewStore(cfg.DataDir),
		buildInfo:     buildInfo,
		cancelFunc:    cancelFunc,
		highlights:    make(map[string]string),
		sessionID:     generateSessionID(),
		settings: Settings{
			ProxyPort:           cfg.ProxyPort,
			UIPort:              cfg.UIPort,
			InterceptEnabled:    false,
			InterceptTimeout:    60,
			HTTP2Enabled:        true,
			KeepAliveEnabled:    false,
			MaxRequests:         store.MaxSize(),
			DisableUpdateChecks: cfg.DisableUpdateChecks,
		},
	}
}

// RestartRequested returns true if the server was shut down for a restart (e.g. after update).
func (s *APIServer) RestartRequested() bool {
	return s.restart
}

// NewListenerMode creates an APIServer in listener mode (no proxy components).
func NewListenerMode(cfg config.Config, cbStore *callback.Store, xssStore *xsshunter.Store, hub *Hub, token string) *APIServer {
	return &APIServer{
		cfg:          cfg,
		hub:          hub,
		cbStore:      cbStore,
		xssStore:     xssStore,
		listenerMode: true,
		teamToken:    token,
		sessionID:    generateSessionID(),
		settings: Settings{
			UIPort: cfg.UIPort,
		},
	}
}

// NewTeamServerMode creates an APIServer in team server mode (listener + team features, no frontend).
func NewTeamServerMode(cfg config.Config, cbStore *callback.Store, xssStore *xsshunter.Store, hub *Hub, teamStore *team.Store, token string) *APIServer {
	hub.SetOnConnect(func(nickname, ip string) {
		if err := teamStore.RecordConnection(nickname, ip); err != nil {
			log.Printf("team: failed to record connection for %s: %v", nickname, err)
		}
	})
	return &APIServer{
		cfg:            cfg,
		hub:            hub,
		cbStore:        cbStore,
		xssStore:       xssStore,
		listenerMode:   true,
		teamServerMode: true,
		teamStore:      teamStore,
		teamToken:      token,
		sessionID:      generateSessionID(),
		settings: Settings{
			UIPort: cfg.UIPort,
		},
	}
}

// startUpdateChecker runs a background goroutine that checks for updates every
// 5 minutes and broadcasts a WebSocket event when a new version is found.
func (s *APIServer) startUpdateChecker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.RLock()
				disabled := s.settings.DisableUpdateChecks
				currentVersion := s.buildInfo.Version
				s.mu.RUnlock()

				if disabled {
					continue
				}

				latestVersion, available := update.CheckForUpdate(currentVersion)
				if !available {
					continue
				}

				s.mu.Lock()
				changed := !s.buildInfo.UpdateAvailable || s.buildInfo.LatestVersion != latestVersion
				s.buildInfo.UpdateAvailable = available
				s.buildInfo.LatestVersion = latestVersion
				s.mu.Unlock()

				if changed {
					s.mu.RLock()
					info := s.buildInfo
					s.mu.RUnlock()
					s.hub.Broadcast() <- event.WSEvent{
						Type: "system.update.available",
						Data: info,
					}
				}
			}
		}
	}()
}

// Start begins serving and blocks until ctx is cancelled.
func (s *APIServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	registerRoutes(s, mux)

	// Start periodic update checker (proxy mode only).
	if !s.listenerMode {
		s.startUpdateChecker(ctx)
	}

	// Serve frontend (skip in listener mode - listener is API-only).
	if !s.listenerMode {
		if s.cfg.Dev {
			s.mountDevProxy(mux)
		} else {
			s.mountEmbedded(mux)
		}
	}

	var handler http.Handler = mux
	if s.listenerMode {
		// Listener/teamserver: bearer-token auth.
		handler = team.AuthMiddleware(s.teamToken, handler)
	} else {
		// Proxy mode: restrict the API to same-origin browser requests.
		handler = originGuard(s.cfg, handler)
	}

	s.srv = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.cfg.BindAddr, s.cfg.UIPort),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	if err := s.srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// mountEmbedded serves the built React app from the embedded FS.
func (s *APIServer) mountEmbedded(mux *http.ServeMux) {
	sub, err := fs.Sub(joroweb.Dist, "dist")
	if err != nil {
		return
	}
	mux.Handle("/", http.FileServer(http.FS(&spaFS{fs: sub})))
}

// mountDevProxy reverse-proxies non-API requests to the Vite dev server.
func (s *APIServer) mountDevProxy(mux *http.ServeMux) {
	target, err := url.Parse(s.cfg.ViteURL)
	if err != nil {
		return
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	mux.Handle("/", rp)
}

// spaFS serves index.html for any path not found in the embedded FS (SPA catch-all).
type spaFS struct{ fs fs.FS }

func (s *spaFS) Open(name string) (fs.File, error) {
	f, err := s.fs.Open(name)
	if err == nil {
		return f, nil
	}
	if os.IsNotExist(err) {
		return s.fs.Open("index.html")
	}
	return nil, err
}

// writeJSON encodes data as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
