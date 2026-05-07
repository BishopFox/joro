package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BishopFox/joro/sdk"
)

// handleListPlugins returns all loaded plugins with their status.
func (s *APIServer) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.pluginManager.List())
}

// handleListExecProviders returns built-in execution providers plus any loaded
// plugin providers, each with their config schema.
func (s *APIServer) handleListExecProviders(w http.ResponseWriter, r *http.Request) {
	type providerInfo struct {
		Name         string           `json:"name"`
		Label        string           `json:"label"`
		ConfigSchema []sdk.ConfigField `json:"configSchema"`
		Builtin      bool             `json:"builtin"`
	}

	providers := []providerInfo{
		{Name: "webshell", Label: "Web Shell", Builtin: true},
		{Name: "sliver", Label: "Sliver C2", Builtin: true},
	}

	if s.pluginManager != nil {
		for name, ep := range s.pluginManager.ExecProviders() {
			schema := safeConfigSchema(name, ep)
			providers = append(providers, providerInfo{
				Name:         name,
				Label:        ep.Manifest().Description,
				ConfigSchema: schema,
				Builtin:      false,
			})
		}
	}

	writeJSON(w, http.StatusOK, providers)
}

// handlePluginGraph aggregates network graph data from all connected
// ExecProviders that implement GraphProvider.
func (s *APIServer) handlePluginGraph(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.pluginManager.GraphData(ctx))
}

// makeExtStatusHandler returns a handler for GET /api/v1/plugin/{name}/status.
func (s *APIServer) makeExtStatusHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ep := s.pluginManager.ExecProviders()[name]
		if ep == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}
		status := safeStatus(name, ep, r.Context())
		writeJSON(w, http.StatusOK, status)
	}
}

// makeExtConnectHandler returns a handler for POST /api/v1/plugin/{name}/connect.
func (s *APIServer) makeExtConnectHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ep := s.pluginManager.ExecProviders()[name]
		if ep == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}

		var config map[string]string
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		if err := safeConnect(name, ep, ctx, config); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"connected": true})
	}
}

// makeExtDisconnectHandler returns a handler for POST /api/v1/plugin/{name}/disconnect.
func (s *APIServer) makeExtDisconnectHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ep := s.pluginManager.ExecProviders()[name]
		if ep == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		if err := safeDisconnect(name, ep, ctx); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"connected": false})
	}
}

// makeExtCommandHandler returns a handler for POST /api/v1/plugin/{name}/command.
func (s *APIServer) makeExtCommandHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ep := s.pluginManager.ExecProviders()[name]
		if ep == nil {
			writeError(w, http.StatusNotFound, "plugin not found")
			return
		}

		var body struct {
			Input string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if strings.TrimSpace(body.Input) == "" {
			writeError(w, http.StatusBadRequest, "input is required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		result := safeCommand(name, ep, ctx, body.Input)
		writeJSON(w, http.StatusOK, result)
	}
}

// handleUploadPlugin accepts a multipart .so/.dylib file upload and saves it
// to the plugins directory. A restart is required to load the new plugin.
func (s *APIServer) handleUploadPlugin(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		writeError(w, http.StatusInternalServerError, "plugin manager not initialized")
		return
	}

	// 32 MB max upload.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)
	if !strings.HasSuffix(filename, ".so") && !strings.HasSuffix(filename, ".dylib") {
		writeError(w, http.StatusBadRequest, "file must be a .so or .dylib")
		return
	}

	dest := filepath.Join(s.pluginManager.PluginDir(), filename)

	// Prevent symlink attacks: if the destination exists and is a symlink,
	// refuse the upload rather than following it to an arbitrary path.
	if info, err := os.Lstat(dest); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			writeError(w, http.StatusBadRequest, "destination is a symlink")
			return
		}
	}

	// Write with restrictive permissions (owner-only).
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create file: %v", err))
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		os.Remove(dest)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("write file: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"filename": filename,
		"message":  "plugin uploaded — restart Joro to load it",
	})
}

// handleDeletePlugin removes a plugin file from the plugins directory.
// A restart is required for the change to take effect.
func (s *APIServer) handleDeletePlugin(w http.ResponseWriter, r *http.Request) {
	if s.pluginManager == nil {
		writeError(w, http.StatusInternalServerError, "plugin manager not initialized")
		return
	}

	filename := r.PathValue("filename")
	if filename == "" {
		writeError(w, http.StatusBadRequest, "filename is required")
		return
	}

	// Sanitize: only allow base filenames, no path traversal.
	filename = filepath.Base(filename)
	if !strings.HasSuffix(filename, ".so") && !strings.HasSuffix(filename, ".dylib") {
		writeError(w, http.StatusBadRequest, "invalid plugin filename")
		return
	}

	path := filepath.Join(s.pluginManager.PluginDir(), filename)

	// Refuse to delete through a symlink.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			writeError(w, http.StatusBadRequest, "target is a symlink")
			return
		}
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "plugin file not found")
		} else {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("remove file: %v", err))
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"filename": filename,
		"message":  "plugin removed — restart Joro to apply",
	})
}

// registerPluginRoutes registers all dynamic routes for loaded plugins.
// Called from registerRoutes() after the static route block.
func registerPluginRoutes(s *APIServer, mux *http.ServeMux) {
	if s.pluginManager == nil {
		return
	}

	// Plugin listing, upload, delete, graph.
	mux.HandleFunc("GET /api/v1/plugins", s.handleListPlugins)
	mux.HandleFunc("POST /api/v1/plugins/upload", s.handleUploadPlugin)
	mux.HandleFunc("DELETE /api/v1/plugins/{filename}", s.handleDeletePlugin)
	mux.HandleFunc("GET /api/v1/plugins/exec-providers", s.handleListExecProviders)
	mux.HandleFunc("GET /api/v1/plugins/interact-providers", s.handleListInteractProviders)
	mux.HandleFunc("GET /api/v1/plugins/graph", s.handlePluginGraph)

	// Per exec provider routes.
	for name := range s.pluginManager.ExecProviders() {
		p := "/api/v1/plugin/" + name
		mux.HandleFunc("GET "+p+"/status", s.makeExtStatusHandler(name))
		mux.HandleFunc("POST "+p+"/connect", s.makeExtConnectHandler(name))
		mux.HandleFunc("POST "+p+"/disconnect", s.makeExtDisconnectHandler(name))
		mux.HandleFunc("POST "+p+"/command", s.makeExtCommandHandler(name))
	}

	// Per interact provider routes.
	for name := range s.pluginManager.InteractProviders() {
		p := "/api/v1/plugin/" + name + "/interact"
		mux.HandleFunc("GET "+p+"/instances", s.makeInteractListInstancesHandler(name))
		mux.HandleFunc("POST "+p+"/instances", s.makeInteractCreateInstanceHandler(name))
		mux.HandleFunc("DELETE "+p+"/instances/{id}", s.makeInteractDeleteInstanceHandler(name))
		mux.HandleFunc("PUT "+p+"/instances/{id}/enabled", s.makeInteractSetEnabledHandler(name))
		mux.HandleFunc("GET "+p+"/interactions", s.makeInteractListInteractionsHandler(name))
		mux.HandleFunc("DELETE "+p+"/interactions", s.makeInteractClearInteractionsHandler(name))
	}

	// Tab + feature routes and UI assets.
	for name, tab := range s.pluginManager.TabProviders() {
		registerTabExtRoutes(mux, name, tab)
	}
	for name, feat := range s.pluginManager.Features() {
		registerTabExtRoutes(mux, name, feat)
	}

	// Dashboard plugin routes + UI.
	if dash := s.pluginManager.Dashboard(); dash != nil {
		dname := dash.Manifest().Name
		for _, route := range dash.Routes() {
			pattern := route.Method + " /api/v1/plugin/" + dname + route.Pattern
			mux.HandleFunc(pattern, route.Handler)
		}
		if assets := dash.UIAssets(); assets != nil {
			prefix := "/plugin/" + dname + "/"
			mux.Handle(prefix, http.StripPrefix(prefix, http.FileServer(http.FS(assets))))
		}
	}
}

// registerTabExtRoutes registers a TabProvider's API routes and UI assets.
func registerTabExtRoutes(mux *http.ServeMux, name string, tab sdk.TabProvider) {
	for _, route := range tab.Routes() {
		pattern := route.Method + " /api/v1/plugin/" + name + route.Pattern
		mux.HandleFunc(pattern, route.Handler)
	}
	if assets := tab.UIAssets(); assets != nil {
		sub, err := fs.Sub(assets, ".")
		if err != nil {
			log.Printf("[plugins] %s: UI assets error: %v", name, err)
			return
		}
		prefix := "/plugin/" + name + "/"
		mux.Handle(prefix, http.StripPrefix(prefix, http.FileServer(http.FS(sub))))
	}
}

// ---------------------------------------------------------------------------
// Panic-safe wrappers for ExecProvider methods
// ---------------------------------------------------------------------------

func safeConfigSchema(name string, ep sdk.ExecProvider) (schema []sdk.ConfigField) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[plugins] %s: ConfigSchema panic: %v", name, r)
			schema = nil
		}
	}()
	return ep.ConfigSchema()
}

func safeStatus(name string, ep sdk.ExecProvider, ctx context.Context) (status sdk.ProviderStatus) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[plugins] %s: Status panic: %v", name, r)
			status = sdk.ProviderStatus{}
		}
	}()
	return ep.Status(ctx)
}

func safeConnect(name string, ep sdk.ExecProvider, ctx context.Context, config map[string]string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: Connect panic: %v", name, r)
		}
	}()
	return ep.Connect(ctx, config)
}

func safeDisconnect(name string, ep sdk.ExecProvider, ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[plugins] %s: Disconnect panic: %v", name, r)
		}
	}()
	return ep.Disconnect(ctx)
}

func safeCommand(name string, ep sdk.ExecProvider, ctx context.Context, input string) (result sdk.CommandResult) {
	defer func() {
		if r := recover(); r != nil {
			result = sdk.CommandResult{Error: fmt.Sprintf("plugin panic: %v", r)}
			log.Printf("[plugins] %s: Command panic: %v", name, r)
		}
	}()
	return ep.Command(ctx, input)
}
