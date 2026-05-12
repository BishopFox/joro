package plugins

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/sdk"
)

// PluginInfo is the API-facing summary of a loaded plugin.
type PluginInfo struct {
	Name     string         `json:"name"`
	Version  string         `json:"version"`
	Desc     string         `json:"description"`
	Type     sdk.PluginType `json:"type"`
	Status   string         `json:"status"`             // "loaded", "error"
	Error    string         `json:"error,omitempty"`
	Hash     string         `json:"hash"`               // SHA-256 of .so file
	Filename string         `json:"filename"`            // original .so/.dylib filename
	HasGraph bool           `json:"hasGraph,omitempty"`  // exec provider implements GraphProvider
	TabLabel string         `json:"tabLabel,omitempty"`  // for tab/feature/dashboard types
}

// Manager loads, categorizes, and manages the lifecycle of plugins.
type Manager struct {
	mu                sync.RWMutex
	pluginDir         string
	execProviders     map[string]sdk.ExecProvider
	tabProviders      map[string]sdk.TabProvider
	features          map[string]sdk.TabProvider
	interactProviders map[string]sdk.InteractProvider
	proxyHooks        []sdk.ProxyHook
	dashboard         sdk.DashboardProvider
	allPlugins        []PluginInfo
	broadcast         chan<- any
}

// NewManager creates a plugin manager that loads plugins from pluginDir.
func NewManager(pluginDir string, broadcast chan<- any) *Manager {
	return &Manager{
		pluginDir:         pluginDir,
		execProviders:     make(map[string]sdk.ExecProvider),
		tabProviders:      make(map[string]sdk.TabProvider),
		features:          make(map[string]sdk.TabProvider),
		interactProviders: make(map[string]sdk.InteractProvider),
		broadcast:         broadcast,
	}
}

// Start loads all plugins from the plugin directory, categorizes them by type,
// and calls Init() on each. Errors during loading or init are logged but do not
// prevent other plugins from loading.
func (m *Manager) Start(ctx context.Context) error {
	// Ensure plugin directory exists.
	if err := os.MkdirAll(m.pluginDir, 0o700); err != nil {
		return fmt.Errorf("create plugin dir: %w", err)
	}

	plugins, errs := loadPlugins(m.pluginDir)
	for _, err := range errs {
		log.Printf("[plugins] %v", err)
	}

	for _, lp := range plugins {
		manifest := lp.ext.Manifest()
		info := PluginInfo{
			Name:     manifest.Name,
			Version:  manifest.Version,
			Desc:     manifest.Description,
			Type:     manifest.Type,
			Status:   "loaded",
			Hash:     lp.hash,
			Filename: lp.filename,
		}

		// Create scoped data directory for this plugin.
		dataDir := filepath.Join(filepath.Dir(m.pluginDir), "plugin-data", manifest.Name)
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			info.Status = "error"
			info.Error = fmt.Sprintf("create data dir: %v", err)
			m.allPlugins = append(m.allPlugins, info)
			log.Printf("[plugins] %s: %s", manifest.Name, info.Error)
			continue
		}

		// Init with panic recovery.
		extCtx := sdk.PluginContext{
			DataDir:   dataDir,
			Broadcast: newScopedBroadcast(manifest.Name, m.broadcast),
		}
		if err := safeInit(lp.ext, extCtx); err != nil {
			info.Status = "error"
			info.Error = fmt.Sprintf("init: %v", err)
			m.allPlugins = append(m.allPlugins, info)
			log.Printf("[plugins] %s init failed: %v", manifest.Name, err)
			continue
		}

		// Categorize by type.
		switch manifest.Type {
		case sdk.TypeExecProvider:
			ep, ok := lp.ext.(sdk.ExecProvider)
			if !ok {
				info.Status = "error"
				info.Error = "does not implement ExecProvider interface"
			} else {
				m.execProviders[manifest.Name] = ep
				if _, hasGraph := lp.ext.(sdk.GraphProvider); hasGraph {
					info.HasGraph = true
				}
			}

		case sdk.TypeTab:
			tp, ok := lp.ext.(sdk.TabProvider)
			if !ok {
				info.Status = "error"
				info.Error = "does not implement TabProvider interface"
			} else {
				m.tabProviders[manifest.Name] = tp
				info.TabLabel = tp.TabInfo().Label
			}

		case sdk.TypeFeature:
			fp, ok := lp.ext.(sdk.TabProvider)
			if !ok {
				info.Status = "error"
				info.Error = "does not implement TabProvider interface"
			} else {
				m.features[manifest.Name] = fp
				info.TabLabel = fp.TabInfo().Label
			}

		case sdk.TypeProxyHook:
			ph, ok := lp.ext.(sdk.ProxyHook)
			if !ok {
				info.Status = "error"
				info.Error = "does not implement ProxyHook interface"
			} else {
				m.proxyHooks = append(m.proxyHooks, ph)
			}

		case sdk.TypeDashboard:
			dp, ok := lp.ext.(sdk.DashboardProvider)
			if !ok {
				info.Status = "error"
				info.Error = "does not implement DashboardProvider interface"
			} else if m.dashboard != nil {
				info.Status = "error"
				info.Error = "only one dashboard plugin can be active"
			} else {
				m.dashboard = dp
				info.TabLabel = manifest.Name
			}

		case sdk.TypeInteractProvider:
			ip, ok := lp.ext.(sdk.InteractProvider)
			if !ok {
				info.Status = "error"
				info.Error = "does not implement InteractProvider interface"
			} else {
				m.interactProviders[manifest.Name] = ip
				info.TabLabel = ip.Info().Label
			}
		}

		m.allPlugins = append(m.allPlugins, info)
		log.Printf("[plugins] loaded %s v%s (%s) [%s]", manifest.Name, manifest.Version, manifest.Type, lp.hash[:12])
	}

	return nil
}

// Shutdown calls Shutdown() on each loaded plugin with panic recovery.
func (m *Manager) Shutdown() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, ep := range m.execProviders {
		safeShutdown(name, ep)
	}
	for name, tp := range m.tabProviders {
		safeShutdown(name, tp)
	}
	for name, fp := range m.features {
		safeShutdown(name, fp)
	}
	for name, ip := range m.interactProviders {
		safeShutdown(name, ip)
	}
	for _, ph := range m.proxyHooks {
		safeShutdown(ph.Manifest().Name, ph)
	}
	if m.dashboard != nil {
		safeShutdown(m.dashboard.Manifest().Name, m.dashboard)
	}
}

// List returns info about all loaded plugins.
func (m *Manager) List() []PluginInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PluginInfo, len(m.allPlugins))
	copy(out, m.allPlugins)
	return out
}

// ExecProviders returns the loaded execution providers.
func (m *Manager) ExecProviders() map[string]sdk.ExecProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.execProviders
}

// TabProviders returns the loaded top-level tab plugins.
func (m *Manager) TabProviders() map[string]sdk.TabProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tabProviders
}

// Features returns the loaded plugin features (sub-tabs).
func (m *Manager) Features() map[string]sdk.TabProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.features
}

// InteractProviders returns the loaded Interact-tab OOB plugins.
func (m *Manager) InteractProviders() map[string]sdk.InteractProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.interactProviders
}

// ProxyHooks returns the loaded proxy hooks in load order.
func (m *Manager) ProxyHooks() []sdk.ProxyHook {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.proxyHooks
}

// Dashboard returns the loaded dashboard plugin, or nil.
func (m *Manager) Dashboard() sdk.DashboardProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dashboard
}

// PluginDir returns the directory where plugin .so/.dylib files are stored.
func (m *Manager) PluginDir() string {
	return m.pluginDir
}

// HasPlugins returns true if any plugins are loaded.
func (m *Manager) HasPlugins() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.allPlugins) > 0
}

// GraphData collects network graph data from all connected ExecProviders that
// implement GraphProvider. Returns a map keyed by provider name.
func (m *Manager) GraphData(ctx context.Context) map[string]sdk.GraphInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]sdk.GraphInfo)
	for name, ep := range m.execProviders {
		gp, ok := ep.(sdk.GraphProvider)
		if !ok || !ep.IsConnected() {
			continue
		}
		info, err := safeGraphData(ctx, name, gp)
		if err != nil {
			log.Printf("[plugins] %s: graph data error: %v", name, err)
			continue
		}
		result[name] = info
	}
	return result
}

// RunRequestHook chains all proxy hooks' OnRequest methods.
// Returns the (possibly modified) raw request, or nil to drop.
func (m *Manager) RunRequestHook(ctx context.Context, info sdk.RequestInfo, rawReq []byte) ([]byte, error) {
	m.mu.RLock()
	hooks := m.proxyHooks
	m.mu.RUnlock()

	current := rawReq
	for _, hook := range hooks {
		result, err := safeOnRequest(ctx, hook, info, current)
		if err != nil {
			log.Printf("[plugins] %s: request hook error: %v", hook.Manifest().Name, err)
			continue // skip this hook, use current value
		}
		if result == nil {
			return nil, nil // drop
		}
		current = result
	}
	return current, nil
}

// RunResponseHook chains all proxy hooks' OnResponse methods.
func (m *Manager) RunResponseHook(ctx context.Context, info sdk.RequestInfo, rawResp []byte) ([]byte, error) {
	m.mu.RLock()
	hooks := m.proxyHooks
	m.mu.RUnlock()

	current := rawResp
	for _, hook := range hooks {
		result, err := safeOnResponse(ctx, hook, info, current)
		if err != nil {
			log.Printf("[plugins] %s: response hook error: %v", hook.Manifest().Name, err)
			continue
		}
		if result != nil {
			current = result
		}
	}
	return current, nil
}

// ---------------------------------------------------------------------------
// State persistence helpers
// ---------------------------------------------------------------------------

// allPluginsForState returns every currently loaded plugin keyed by name.
// Plugins appear once regardless of how many interfaces they satisfy.
func (m *Manager) allPluginsForState() map[string]sdk.Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]sdk.Plugin)
	for name, ep := range m.execProviders {
		out[name] = ep
	}
	for name, tp := range m.tabProviders {
		out[name] = tp
	}
	for name, fp := range m.features {
		out[name] = fp
	}
	for name, ip := range m.interactProviders {
		out[name] = ip
	}
	for _, ph := range m.proxyHooks {
		out[ph.Manifest().Name] = ph
	}
	if m.dashboard != nil {
		out[m.dashboard.Manifest().Name] = m.dashboard
	}
	return out
}

// ExportUserStates walks every loaded plugin and returns state bytes for those
// that implement sdk.UserStatefulPlugin. Plugins whose ExportUserState panics
// or errors are skipped with a log line; the returned map only contains
// successful exports.
func (m *Manager) ExportUserStates() map[string][]byte {
	out := make(map[string][]byte)
	for name, plug := range m.allPluginsForState() {
		usp, ok := plug.(sdk.UserStatefulPlugin)
		if !ok {
			continue
		}
		data, err := safeExportUserState(usp)
		if err != nil {
			log.Printf("[plugins] %s: export user state: %v", name, err)
			continue
		}
		out[name] = data
	}
	return out
}

// ApplyUserStates calls ImportUserState on each loaded UserStatefulPlugin whose
// name appears in states. Returns names that did not match a loaded
// UserStatefulPlugin so callers can preserve those blobs across round-trips.
func (m *Manager) ApplyUserStates(states map[string][]byte) []string {
	loaded := m.allPluginsForState()
	var unknown []string
	for name, data := range states {
		plug, ok := loaded[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		usp, ok := plug.(sdk.UserStatefulPlugin)
		if !ok {
			// Plugin is loaded but doesn't opt in to user-scoped state —
			// treat as unknown so the blob is preserved on re-save.
			unknown = append(unknown, name)
			continue
		}
		if err := safeImportUserState(usp, data); err != nil {
			log.Printf("[plugins] %s: import user state: %v", name, err)
		}
	}
	return unknown
}

// ExportProjectStates is the ProjectStatefulPlugin analogue of ExportUserStates.
func (m *Manager) ExportProjectStates() map[string][]byte {
	out := make(map[string][]byte)
	for name, plug := range m.allPluginsForState() {
		psp, ok := plug.(sdk.ProjectStatefulPlugin)
		if !ok {
			continue
		}
		data, err := safeExportProjectState(psp)
		if err != nil {
			log.Printf("[plugins] %s: export project state: %v", name, err)
			continue
		}
		out[name] = data
	}
	return out
}

// ApplyProjectStates is the ProjectStatefulPlugin analogue of ApplyUserStates.
func (m *Manager) ApplyProjectStates(states map[string][]byte) []string {
	loaded := m.allPluginsForState()
	var unknown []string
	for name, data := range states {
		plug, ok := loaded[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		psp, ok := plug.(sdk.ProjectStatefulPlugin)
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if err := safeImportProjectState(psp, data); err != nil {
			log.Printf("[plugins] %s: import project state: %v", name, err)
		}
	}
	return unknown
}

// ---------------------------------------------------------------------------
// Scoped broadcast channel
// ---------------------------------------------------------------------------

// scopedBroadcast wraps a broadcast channel to automatically prefix event types
// with "ext.{name}.", preventing plugins from spoofing built-in events.
type scopedBroadcast struct {
	prefix string
	inner  chan<- any
}

func newScopedBroadcast(name string, inner chan<- any) chan<- sdk.Event {
	sb := &scopedBroadcast{
		prefix: "plugin." + name + ".",
		inner:  inner,
	}
	ch := make(chan sdk.Event, 64)
	go func() {
		for ev := range ch {
			wsEvent := event.WSEvent{
				Type: sb.prefix + ev.Type,
				Data: ev.Data,
			}
			select {
			case sb.inner <- wsEvent:
			default:
			}
		}
	}()
	return ch
}

// ---------------------------------------------------------------------------
// Panic-safe wrappers
// ---------------------------------------------------------------------------

func safeInit(ext sdk.Plugin, ctx sdk.PluginContext) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return ext.Init(ctx)
}

func safeShutdown(name string, ext sdk.Plugin) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[plugins] %s: shutdown panic: %v", name, r)
		}
	}()
	if err := ext.Shutdown(); err != nil {
		log.Printf("[plugins] %s: shutdown error: %v", name, err)
	}
}

func safeGraphData(ctx context.Context, name string, gp sdk.GraphProvider) (info sdk.GraphInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return gp.GraphData(ctx), nil
}

func safeOnRequest(ctx context.Context, hook sdk.ProxyHook, info sdk.RequestInfo, rawReq []byte) (result []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return hook.OnRequest(ctx, info, rawReq)
}

func safeOnResponse(ctx context.Context, hook sdk.ProxyHook, info sdk.RequestInfo, rawResp []byte) (result []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return hook.OnResponse(ctx, info, rawResp)
}

func safeExportUserState(p sdk.UserStatefulPlugin) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return p.ExportUserState()
}

func safeImportUserState(p sdk.UserStatefulPlugin, data []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return p.ImportUserState(data)
}

func safeExportProjectState(p sdk.ProjectStatefulPlugin) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return p.ExportProjectState()
}

func safeImportProjectState(p sdk.ProjectStatefulPlugin, data []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return p.ImportProjectState(data)
}
