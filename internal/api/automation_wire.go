package api

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/automation"
	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/capreg"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/mcp"
)

// SetAutomation installs the automation token store and builds the capability
// registry over it.
//
// It is a setter rather than another parameter on New, which already takes
// fifteen; this follows SetHookRunner and SetOnEvent. Passing nil leaves every
// /api/v1/automation route unregistered, binds no second port, and starts no
// goroutine — which is the default, since main.go only calls this when the token
// file could be opened and --no-automation was not given.
//
// The registry is built here rather than in main.go because detectFindings and
// detectEngine are constructed inside New, and moving them out would be a
// behavior-adjacent refactor of code whose placement is deliberately commented.
func (s *APIServer) SetAutomation(store *automation.Store) {
	if store == nil || s.listenerMode {
		return
	}
	s.autoStore = store
	s.capAudit = capability.NewAuditLog(capability.DefaultAuditSize)
	s.capContexts = httptools.NewContexts()
	s.capRegistry = capreg.Build(capreg.Deps{
		Store:    s.store,
		Scope:    s.scope,
		Findings: s.detectFindings,
		Engine:   s.detectEngine,
		Notes:    s.noteStore,
		WSStore:  s.wsStore,
		CA:       s.ca,
		// Automation sends go through Joro's own proxy so they are captured,
		// scoped and rewritten exactly like browser traffic. BindAddr rather than
		// a hardcoded loopback: an operator who bound the proxy elsewhere still
		// needs this to reach it.
		ProxyAddr: fmt.Sprintf("%s:%d", s.cfg.BindAddr, s.cfg.ProxyPort),
		Version:   s.buildInfo.Version,

		ActiveProject: func() string {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return s.activeProjectConfig
		},

		// The rule stores behind the config-class capabilities. Settings is
		// deliberately not among them: it lives on this struct behind s.mu, and it is
		// where the knobs that would matter most are — SOCKS, the team token, the
		// listener URL.
		Replace:    s.replace,
		CustomData: s.customData,
		Noise:      s.noise,
		Intercept:  s.intercept,

		// A getter rather than the context itself: this runs before StartDetectLoop,
		// so s.detectCtx is still nil here. detectBackgroundCtx already falls back to
		// context.Background when the loop never started.
		Scanner: s.detectScanner,
		BgCtx:   s.detectBackgroundCtx,

		Contexts:  s.capContexts,
		Fuzzer:    s.fuzzerStore,
		Transport: s.transport,

		Privileged: s.cfg.AutomationPrivileged,
		Sliver:     s.sliverClient,
		Mythic:     s.mythicClient,

		Broadcast: s.hub.Broadcast(),
	}, s.capAudit)
	s.mcpListener = mcp.NewListener()

	if s.cfg.AutomationPrivileged {
		var ids []string
		for _, c := range s.capRegistry.All() {
			if c.Privileged {
				ids = append(ids, c.ID)
			}
		}
		log.Printf("[automation] --automation-privileged: %s are grantable to an automation token. "+
			"No profile includes them; grant each by hand.", strings.Join(ids, " "))
	}
}

// automationEnabled reports whether the automation surface is available.
func (s *APIServer) automationEnabled() bool {
	return s.autoStore != nil && s.capRegistry != nil
}

// startAutomation brings up the persisted MCP listener state and the token
// store's flush loop. Called from Start once the server context exists.
func (s *APIServer) startAutomation(ctx context.Context) {
	if !s.automationEnabled() {
		return
	}
	s.autoStore.StartFlushLoop(ctx)
	s.mcpListener.CloseOnContext(ctx)

	state := s.autoStore.MCP()
	if !state.Enabled {
		return
	}
	if err := s.startMCPListener(state.Port); err != nil {
		// Non-fatal: a port conflict at startup must not stop Joro. The UI shows
		// the error on the Automation page, which is where an operator would look.
		log.Printf("[automation] MCP listener: %v", err)
	}
}

// startMCPListener binds and serves the MCP endpoint.
//
// It refuses with zero tokens configured. An unauthenticated MCP server on
// loopback is a local privilege-escalation gadget for every other process on the
// machine, including a browser extension — and since the tools include sending
// traffic through the operator's engagement proxy, that is not a theoretical
// concern.
func (s *APIServer) startMCPListener(port int) error {
	if !s.automationEnabled() {
		return fmt.Errorf("automation is not configured")
	}
	if s.autoStore.Count() == 0 {
		return fmt.Errorf("create an automation token before enabling the MCP listener: " +
			"an MCP server with no tokens would accept any local process")
	}
	srv := mcp.NewServer(s.capRegistry, s.autoStore, s.buildInfo.Version)
	if err := s.mcpListener.Start(port, srv.Handler()); err != nil {
		s.broadcastMCPState()
		return err
	}
	s.broadcastMCPState()
	return nil
}

func (s *APIServer) stopMCPListener() error {
	if s.mcpListener == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.mcpListener.Stop(ctx)
	s.broadcastMCPState()
	return err
}

// mcpStateView is the shape the UI renders.
type mcpStateView struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Port     int    `json:"port"`
	Endpoint string `json:"endpoint"`
	Error    string `json:"error,omitempty"`
	// TokenCount lets the UI explain why enabling is refused before the operator
	// tries it.
	TokenCount int `json:"tokenCount"`
}

func (s *APIServer) mcpState() mcpStateView {
	if !s.automationEnabled() {
		return mcpStateView{}
	}
	persisted := s.autoStore.MCP()
	running, port, lastErr := s.mcpListener.Running()
	if port == 0 {
		port = persisted.Port
	}
	return mcpStateView{
		Enabled:    persisted.Enabled,
		Running:    running,
		Port:       port,
		Endpoint:   fmt.Sprintf("http://127.0.0.1:%d/mcp", port),
		Error:      lastErr,
		TokenCount: s.autoStore.Count(),
	}
}

// broadcastMCPState pushes listener state to open UI clients.
//
// This is the only automation WebSocket event. An event per invocation would be a
// firehose the *agent* controls, on a channel shared with proxy traffic; the
// Activity view polls instead.
func (s *APIServer) broadcastMCPState() {
	if s.hub == nil {
		return
	}
	select {
	case s.hub.Broadcast() <- event.WSEvent{Type: "automation.mcp.state", Data: s.mcpState()}:
	default:
	}
}
