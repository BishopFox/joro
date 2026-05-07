// Package sdk defines the interfaces and types for Joro plugins.
//
// Plugins are shared objects (.so/.dylib) that implement one of the plugin
// interfaces. Each plugin must export a package-level variable named "Plugin"
// of type sdk.Plugin.
//
// Example:
//
//	package main
//
//	import "github.com/BishopFox/joro/sdk"
//
//	var Plugin sdk.Plugin = &MyPlugin{}
//
// Build with: go build -buildmode=plugin -o my-plugin.so .
// Place the resulting file in ~/.joro/plugins/ and restart Joro.
package sdk

import (
	"context"
	"io/fs"
	"net/http"
	"time"
)

// ---------------------------------------------------------------------------
// Base
// ---------------------------------------------------------------------------

// Plugin is the base interface all plugins must implement.
type Plugin interface {
	// Manifest returns metadata describing the plugin.
	Manifest() Manifest

	// Init is called once after the plugin is loaded. The provided context
	// contains a scoped data directory and a broadcast channel for emitting
	// WebSocket events.
	Init(ctx PluginContext) error

	// Shutdown is called when Joro is exiting. Release resources here.
	Shutdown() error
}

// Manifest describes a plugin's identity and type.
type Manifest struct {
	Name        string     `json:"name"`        // URL-safe slug: ^[a-z0-9][a-z0-9_-]*$
	Version     string     `json:"version"`     // semver recommended
	Description string     `json:"description"` // short human-readable summary
	Type        PluginType `json:"type"`
}

// PluginType identifies the kind of integration a plugin provides.
type PluginType string

const (
	TypeExecProvider     PluginType = "exec_provider"     // Execute tab mode
	TypeTab              PluginType = "tab"               // top-level nav tab
	TypeFeature          PluginType = "feature"           // sub-tab in Plugins page
	TypeProxyHook        PluginType = "proxy_hook"        // proxy pipeline hook
	TypeDashboard        PluginType = "dashboard"         // custom dashboard replacement
	TypeInteractProvider PluginType = "interact_provider" // Interact tab OOB source
)

// PluginContext is provided by Joro to the plugin during Init().
type PluginContext struct {
	// DataDir is a directory scoped to this plugin (~/.joro/plugin-data/{name}/).
	// The plugin may read/write files here. The directory is created
	// automatically before Init is called.
	DataDir string

	// Broadcast sends events to all connected WebSocket clients. Events sent
	// on this channel are automatically prefixed with "ext.{name}." to prevent
	// collisions with built-in event types.
	Broadcast chan<- Event
}

// Event is a WebSocket event that can be broadcast to connected clients.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// ---------------------------------------------------------------------------
// Optional state persistence
// ---------------------------------------------------------------------------
//
// Joro has two independent config-file systems: User Configs (operator-level,
// travel with the person) and Project Configs (engagement-level, travel with
// the project). Plugins opt into persistence by implementing one or both of
// the interfaces below. Exported bytes are fully opaque to the host — each
// plugin owns its own schema, encoding, and migration logic.
//
// Persistence is strictly tied to the user's explicit Save Config action;
// Joro does not autosave state on shutdown or on a timer.

// UserStatefulPlugin opts into persistence scoped to User Configs.
// Use this for operator-level state that should travel with the person
// (API keys, personal auth tokens, per-operator UI preferences).
//
// ExportUserState is called when the user saves a User Config.
// ImportUserState is called when the user loads a User Config.
// ImportUserState returning an error is non-fatal — it is logged and the
// plugin continues with its prior state.
type UserStatefulPlugin interface {
	Plugin
	ExportUserState() ([]byte, error)
	ImportUserState(data []byte) error
}

// ProjectStatefulPlugin opts into persistence scoped to Project Configs.
// Use this for engagement-level state that should travel with the project
// (active sessions, instance configurations, captured artifacts).
//
// ExportProjectState is called when the user saves a Project Config.
// ImportProjectState is called when the user loads a Project Config.
// ImportProjectState returning an error is non-fatal.
type ProjectStatefulPlugin interface {
	Plugin
	ExportProjectState() ([]byte, error)
	ImportProjectState(data []byte) error
}

// ---------------------------------------------------------------------------
// Execution Provider
// ---------------------------------------------------------------------------

// ExecProvider integrates into the Execute tab as an additional execution mode.
// The terminal UI (output display, command input, history) is managed by Joro;
// the plugin provides connection lifecycle and command dispatch.
type ExecProvider interface {
	Plugin

	// ConfigSchema describes the fields shown in the connection form.
	// Joro renders these dynamically — no custom frontend code is needed.
	ConfigSchema() []ConfigField

	// Connect establishes a connection using the values from the config form.
	// The keys in config correspond to ConfigField.Name.
	Connect(ctx context.Context, config map[string]string) error

	// Disconnect tears down the connection.
	Disconnect(ctx context.Context) error

	// IsConnected returns whether the provider is currently connected.
	IsConnected() bool

	// Status returns display information shown when connected.
	Status(ctx context.Context) ProviderStatus

	// Command dispatches a text command typed in the terminal and returns
	// the result to be displayed.
	Command(ctx context.Context, input string) CommandResult

	// PromptPrefix returns the terminal prompt string (e.g., "myc2 > ").
	PromptPrefix() string
}

// GraphProvider is optionally implemented by ExecProviders that want to
// contribute nodes to the Dashboard network graph. If an ExecProvider also
// implements GraphProvider, its nodes appear alongside built-in graph nodes.
type GraphProvider interface {
	// GraphData returns server and node information for the network graph.
	// Called periodically by the Dashboard (every 5 seconds).
	GraphData(ctx context.Context) GraphInfo
}

// ConfigField describes one field in the connection config form.
type ConfigField struct {
	Name        string `json:"name"`               // field key, e.g. "serverUrl"
	Label       string `json:"label"`              // display label, e.g. "Server URL"
	Type        string `json:"type"`               // "text", "password", "textarea", "file", "checkbox"
	Placeholder string `json:"placeholder"`        // input placeholder text
	Required    bool   `json:"required"`           // whether the field must be filled
	HelpText    string `json:"helpText,omitempty"` // optional help text shown below the field
}

// ProviderStatus is returned by ExecProvider.Status().
type ProviderStatus struct {
	Connected   bool              `json:"connected"`
	DisplayInfo map[string]string `json:"displayInfo,omitempty"` // key-value pairs shown in the UI
}

// CommandResult is the result of executing a terminal command.
type CommandResult struct {
	Output     string `json:"output"`               // text output displayed in the terminal
	Error      string `json:"error,omitempty"`      // error message (displayed in red)
	DownloadID string `json:"downloadId,omitempty"` // triggers a file download in the UI
	Filename   string `json:"filename,omitempty"`   // filename for the download
	Clear      bool   `json:"clear,omitempty"`      // if true, clears the terminal
}

// GraphInfo contains network graph data for the Dashboard.
type GraphInfo struct {
	Server *GraphServer `json:"server,omitempty"` // the tool's server node
	Nodes  []GraphNode  `json:"nodes"`            // connected sessions, agents, beacons, etc.
}

// GraphServer describes a server node on the network graph.
type GraphServer struct {
	Label string `json:"label"` // display name
	Host  string `json:"host"`
	Port  int    `json:"port"`
}

// GraphNode describes a session/agent/beacon node on the network graph.
type GraphNode struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	RemoteAddress string `json:"remoteAddress"`
	Transport     string `json:"transport"`
	Username      string `json:"username"`
	Type          string `json:"type"`   // "session", "beacon", "agent"
	Status        string `json:"status"` // "active", "stale", "dead"
}

// ---------------------------------------------------------------------------
// Tab / Feature
// ---------------------------------------------------------------------------

// TabProvider adds a navigation tab — either top-level (Type=TypeTab) or as a
// sub-tab within the Plugins page (Type=TypeFeature). The plugin provides
// backend API routes and an optional embedded web UI.
type TabProvider interface {
	Plugin

	// TabInfo returns metadata for the navigation tab.
	TabInfo() TabMeta

	// Routes returns HTTP handlers that Joro registers under
	// /api/v1/plugin/{name}/. The Pattern field is relative (e.g., "/data"
	// becomes /api/v1/plugin/{name}/data).
	Routes() []Route

	// UIAssets returns an embedded filesystem containing the tab's pre-built
	// web UI. Joro serves these files at /plugin/{name}/. Return nil if the
	// plugin has no UI (API-only).
	UIAssets() fs.FS
}

// TabMeta describes a navigation tab.
type TabMeta struct {
	Label string `json:"label"` // display name shown in the nav bar or sub-tab
}

// Route describes an HTTP endpoint registered by a TabProvider or DashboardProvider.
type Route struct {
	Method  string           // HTTP method, e.g. "GET", "POST"
	Pattern string           // relative path, e.g. "/data"
	Handler http.HandlerFunc // the handler function
}

// ---------------------------------------------------------------------------
// Proxy Hook
// ---------------------------------------------------------------------------

// ProxyHook participates in the proxy request/response pipeline.
// Hooks are called in the order plugins were loaded.
type ProxyHook interface {
	Plugin

	// OnRequest is called for each in-scope request after intercept + match/replace,
	// before the request is sent upstream.
	// Return the (possibly modified) rawReq bytes to forward, or nil to drop the request.
	OnRequest(ctx context.Context, info RequestInfo, rawReq []byte) ([]byte, error)

	// OnResponse is called after the upstream response is received, before it is
	// captured and stored.
	// Return the (possibly modified) rawResp bytes, or nil to use the original.
	OnResponse(ctx context.Context, info RequestInfo, rawResp []byte) ([]byte, error)
}

// RequestInfo provides metadata about a proxied request to hook functions.
type RequestInfo struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Host   string `json:"host"`
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

// DashboardProvider replaces the default Dashboard page with a custom UI.
// Only one dashboard plugin can be active at a time.
type DashboardProvider interface {
	Plugin

	// Routes returns HTTP handlers registered under /api/v1/plugin/{name}/.
	Routes() []Route

	// UIAssets returns an embedded filesystem for the custom dashboard UI.
	// Served at /plugin/{name}/.
	UIAssets() fs.FS
}

// ---------------------------------------------------------------------------
// Interact Provider
// ---------------------------------------------------------------------------

// InteractProvider integrates into the Interact tab as an OOB callback source.
// Each provider manages its own list of instances (servers/tokens/tunnels) and
// stores its own interactions. Joro renders the provider's ConfigSchema as a
// horizontal input group in the Interact tab and merges interactions into the
// unified event feed. Broadcasting an event with Type "interaction" on
// PluginContext.Broadcast drives live updates in the UI.
type InteractProvider interface {
	Plugin

	// Info is metadata shown in the plugin's horizontal config group.
	Info() InteractInfo

	// ConfigSchema describes the fields rendered inline for creating a new
	// instance. Joro renders these dynamically — no custom frontend code needed.
	ConfigSchema() []ConfigField

	// CreateInstance creates a new instance (server/token/tunnel) with the
	// supplied config. Instance IDs are opaque strings chosen by the plugin.
	CreateInstance(ctx context.Context, config map[string]string) (InteractInstance, error)

	// ListInstances returns all currently managed instances.
	ListInstances(ctx context.Context) ([]InteractInstance, error)

	// DeleteInstance removes an instance, stopping any polling/clients.
	DeleteInstance(ctx context.Context, id string) error

	// SetInstanceEnabled enables or disables polling for an instance.
	SetInstanceEnabled(ctx context.Context, id string, enabled bool) error

	// ListInteractions returns recorded interactions, optionally filtered by
	// instance ID.
	ListInteractions(ctx context.Context, instanceID string, offset, limit int) (InteractionPage, error)

	// ClearInteractions clears recorded interactions, optionally filtered by
	// instance ID (empty string clears all).
	ClearInteractions(ctx context.Context, instanceID string) error
}

// InteractInfo is display metadata shown in the plugin's config group.
type InteractInfo struct {
	Label       string `json:"label"`              // short provider name, e.g. "Collaborator"
	ButtonLabel string `json:"buttonLabel"`        // add-instance button text, e.g. "Add server"
	HelpText    string `json:"helpText,omitempty"` // optional tooltip
}

// InteractInstance is a configured instance (server/token/tunnel) managed by
// an InteractProvider.
type InteractInstance struct {
	ID         string            `json:"id"`
	Label      string            `json:"label"`      // sidebar text (e.g. "oast.live")
	Hex        string            `json:"hex"`        // correlation token shown in events
	Status     string            `json:"status"`     // "connected" | "connecting" | "error" | "disabled"
	Enabled    bool              `json:"enabled"`
	PayloadURL string            `json:"payloadUrl"`
	Meta       map[string]string `json:"meta,omitempty"`
}

// InteractInteraction is a single recorded OOB interaction (DNS, HTTP, SMTP, ...).
type InteractInteraction struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instanceId"`
	Hex        string    `json:"hex"`      // correlation token
	Protocol   string    `json:"protocol"` // "dns" | "http" | "smtp" | "ftp" | ...
	SourceIP   string    `json:"sourceIp"`
	Timestamp  time.Time `json:"timestamp"`
	QueryName  string    `json:"queryName,omitempty"`
	QueryType  string    `json:"queryType,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	RawRequest string    `json:"rawRequest,omitempty"` // base64-encoded bytes
}

// InteractionPage is a page of interactions returned by ListInteractions.
type InteractionPage struct {
	Items  []InteractInteraction `json:"items"`
	Total  int                   `json:"total"`
	Offset int                   `json:"offset"`
	Limit  int                   `json:"limit"`
}
