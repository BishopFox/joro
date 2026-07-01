package api

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/BishopFox/joro/internal/configstore"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/hashicorp/go-uuid"
)

// --- User Config ---

type userConfigFile struct {
	Version             int               `json:"version"`
	SOCKSHost           string            `json:"socksHost"`
	SOCKSPort           int               `json:"socksPort"`
	SOCKSUsername       string            `json:"socksUsername"`
	SOCKSPassword       string            `json:"socksPassword"`
	SOCKSDNS            bool              `json:"socksDns"`
	HTTP2Enabled        bool              `json:"http2Enabled"`
	KeepAliveEnabled    bool              `json:"keepAliveEnabled"`
	InterceptTimeout    int               `json:"interceptTimeout"`
	MaxRequests         int               `json:"maxRequests"`
	DisableUpdateChecks bool              `json:"disableUpdateChecks"`
	Theme               string            `json:"theme"`
	HiddenTabs          []string          `json:"hiddenTabs,omitempty"`
	PluginStates        map[string]string `json:"pluginStates,omitempty"` // plugin name -> base64(opaque bytes)
}

// --- Project Config ---

type projectScopeRule struct {
	Pattern string   `json:"pattern"`
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
	Include bool     `json:"include"`
}

type projectNoisePattern struct {
	Pattern string `json:"pattern"`
}

type projectReplaceRule struct {
	Target    string `json:"target"`
	MatchType string `json:"matchType"`
	Match     string `json:"match"`
	Replace   string `json:"replace"`
}

type projectCustomItem struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type projectNote struct {
	Host    string `json:"host"`
	Content string `json:"content"`
	Author  string `json:"author"`
}

type projectCapturedRequest struct {
	ID          string `json:"id"`
	Seq         int    `json:"seq"`
	Timestamp   string `json:"timestamp"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Host        string `json:"host"`
	StatusCode  int    `json:"statusCode"`
	ContentType string `json:"contentType,omitempty"`
	DurationNs  int64  `json:"durationNs"`
	ReqRaw      []byte `json:"reqRaw,omitempty"`
	RespRaw     []byte `json:"respRaw,omitempty"`
}

type projectConfigFile struct {
	Version           int                      `json:"version"`
	ProjectID         string                   `json:"projectId,omitempty"`
	ListenerURL       string                   `json:"listenerUrl"`
	TeamToken         string                   `json:"teamToken"`
	TeamNickname      string                   `json:"teamNickname"`
	ScopeEnabled      bool                     `json:"scopeEnabled"`
	ScopeRules        []projectScopeRule       `json:"scopeRules"`
	NoiseEnabled      bool                     `json:"noiseEnabled"`
	NoisePatterns     []projectNoisePattern    `json:"noisePatterns"`
	ReplaceEnabled    bool                     `json:"replaceEnabled"`
	ReplaceRules      []projectReplaceRule     `json:"replaceRules"`
	CustomDataEnabled bool                     `json:"customDataEnabled"`
	CustomDataItems   []projectCustomItem      `json:"customDataItems"`
	Notes             []projectNote            `json:"notes"`
	Highlights        map[string]string        `json:"highlights,omitempty"`
	RequestHistory    []projectCapturedRequest `json:"requestHistory,omitempty"`
	PluginStates      map[string]string        `json:"pluginStates,omitempty"` // plugin name -> base64(opaque bytes)
}

// encodePluginStates base64-encodes each blob for transport inside a JSON
// config file. Returns nil when states is empty so the JSON field is elided.
func encodePluginStates(states map[string][]byte) map[string]string {
	if len(states) == 0 {
		return nil
	}
	out := make(map[string]string, len(states))
	for name, data := range states {
		out[name] = base64.StdEncoding.EncodeToString(data)
	}
	return out
}

// decodePluginStates reverses encodePluginStates. Entries whose value isn't
// valid base64 are dropped with a log line so one corrupt blob doesn't kill
// the whole config load.
func decodePluginStates(encoded map[string]string) map[string][]byte {
	if len(encoded) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(encoded))
	for name, enc := range encoded {
		data, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			log.Printf("[plugins] skipping corrupt state blob for %q: %v", name, err)
			continue
		}
		out[name] = data
	}
	return out
}

// mergePluginStates overlays fresh on top of ghost. Used at save time so blobs
// belonging to plugins not installed on this machine are preserved across a
// load -> save round-trip.
func mergePluginStates(ghost, fresh map[string][]byte) map[string][]byte {
	if len(ghost) == 0 && len(fresh) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(ghost)+len(fresh))
	for name, data := range ghost {
		out[name] = data
	}
	for name, data := range fresh {
		out[name] = data
	}
	return out
}

// buildProjectConfig snapshots the current live state into a projectConfigFile
// (shared by save and export).
func (s *APIServer) buildProjectConfig() projectConfigFile {
	s.mu.RLock()
	listenerURL := s.settings.ListenerURL
	teamToken := s.settings.TeamToken
	teamNickname := s.settings.TeamNickname
	projectID := s.settings.ProjectID
	s.mu.RUnlock()

	scopeRules := s.scope.Rules()
	pScopeRules := make([]projectScopeRule, len(scopeRules))
	for i, r := range scopeRules {
		pScopeRules[i] = projectScopeRule{Pattern: r.Pattern, Methods: r.Methods, Path: r.Path, Include: r.Include}
	}

	noisePatterns := s.noise.Patterns()
	pNoisePatterns := make([]projectNoisePattern, len(noisePatterns))
	for i, p := range noisePatterns {
		pNoisePatterns[i] = projectNoisePattern{Pattern: p.Pattern}
	}

	replaceRules := s.replace.Rules()
	pReplaceRules := make([]projectReplaceRule, len(replaceRules))
	for i, r := range replaceRules {
		pReplaceRules[i] = projectReplaceRule{Target: r.Target, MatchType: r.MatchType, Match: r.Match, Replace: r.Replace}
	}

	customItems := s.customData.Items()
	pCustomItems := make([]projectCustomItem, len(customItems))
	for i, item := range customItems {
		pCustomItems[i] = projectCustomItem{Type: item.Type, Name: item.Name, Value: item.Value}
	}

	var pNotes []projectNote
	if s.noteStore != nil {
		if allNotes, err := s.noteStore.LoadAll(); err == nil {
			pNotes = make([]projectNote, len(allNotes))
			for i, n := range allNotes {
				pNotes[i] = projectNote{Host: n.Host, Content: n.Content, Author: n.Author}
			}
		}
	}

	s.mu.RLock()
	pHighlights := make(map[string]string, len(s.highlights))
	for k, v := range s.highlights {
		pHighlights[k] = v
	}
	projectGhost := s.pendingProjectPluginStates
	s.mu.RUnlock()

	allReqs := s.store.All()
	pReqs := make([]projectCapturedRequest, len(allReqs))
	for i, r := range allReqs {
		pReqs[i] = projectCapturedRequest{
			ID: r.ID, Seq: r.Seq, Timestamp: r.Timestamp.Format(time.RFC3339Nano),
			Method: r.Method, URL: r.URL, Host: r.Host,
			StatusCode: r.StatusCode, ContentType: r.ContentType,
			DurationNs: int64(r.Duration), ReqRaw: r.ReqRaw, RespRaw: r.RespRaw,
		}
	}

	var projectFresh map[string][]byte
	if s.pluginManager != nil {
		projectFresh = s.pluginManager.ExportProjectStates()
	}

	return projectConfigFile{
		Version:           3,
		ProjectID:         projectID,
		ListenerURL:       listenerURL,
		TeamToken:         teamToken,
		TeamNickname:      teamNickname,
		ScopeEnabled:      s.scope.IsEnabled(),
		ScopeRules:        pScopeRules,
		NoiseEnabled:      s.noise.IsEnabled(),
		NoisePatterns:     pNoisePatterns,
		ReplaceEnabled:    s.replace.IsEnabled(),
		ReplaceRules:      pReplaceRules,
		CustomDataEnabled: s.customData.IsEnabled(),
		CustomDataItems:   pCustomItems,
		Notes:             pNotes,
		Highlights:        pHighlights,
		RequestHistory:    pReqs,
		PluginStates:      encodePluginStates(mergePluginStates(projectGhost, projectFresh)),
	}
}

// gzipJSON marshals v to JSON and gzip-compresses it.
func gzipJSON(v any) ([]byte, error) {
	jsonData, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(jsonData); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gunzipIfNeeded decompresses data when it carries the gzip magic bytes,
// capping the decompressed size to guard against gzip bombs. Returns the
// (possibly unchanged) bytes and whether the input was plain (legacy) JSON.
func gunzipIfNeeded(data []byte) (out []byte, legacy bool, err error) {
	const maxDecompressedSize = 2 << 30
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false, err
		}
		defer gz.Close()
		out, err = io.ReadAll(io.LimitReader(gz, maxDecompressedSize+1))
		if err != nil {
			return nil, false, err
		}
		if len(out) > maxDecompressedSize {
			return nil, false, fmt.Errorf("config file exceeds maximum size")
		}
		return out, false, nil
	}
	return data, true, nil
}

// applyProjectConfig applies a parsed project config to live state and returns
// the response map. When preserveNickname is true the caller's current team
// nickname is kept (used when importing someone else's shared project).
func (s *APIServer) applyProjectConfig(cfg *projectConfigFile, name string, preserveNickname bool) map[string]any {
	// Cap request history to the store's capacity.
	maxHistory := s.store.MaxSize()
	if len(cfg.RequestHistory) > maxHistory {
		cfg.RequestHistory = cfg.RequestHistory[len(cfg.RequestHistory)-maxHistory:]
	}

	decodedPluginStates := decodePluginStates(cfg.PluginStates)

	// Apply team server settings.
	s.mu.Lock()
	nickname := cfg.TeamNickname
	if preserveNickname {
		nickname = s.settings.TeamNickname
	}
	teamSettingsChanged := cfg.ListenerURL != s.settings.ListenerURL ||
		cfg.TeamToken != s.settings.TeamToken || nickname != s.settings.TeamNickname
	s.settings.ListenerURL = cfg.ListenerURL
	s.settings.TeamToken = cfg.TeamToken
	s.settings.TeamNickname = nickname
	s.settings.ProjectID = cfg.ProjectID
	s.activeProjectConfig = name
	s.pendingProjectPluginStates = decodedPluginStates
	settings := s.settings
	s.mu.Unlock()

	if teamSettingsChanged && s.listenerRelay != nil {
		s.listenerRelay.Update(settings.ListenerURL, settings.TeamToken, settings.TeamNickname)
	}

	scopeRules := make([]proxy.ScopeRule, len(cfg.ScopeRules))
	for i, r := range cfg.ScopeRules {
		scopeRules[i] = proxy.ScopeRule{ID: proxy.GenerateID(), Pattern: r.Pattern, Methods: r.Methods, Path: r.Path, Include: r.Include}
	}
	s.scope.SetEnabled(cfg.ScopeEnabled)
	s.scope.SetRules(scopeRules)

	noisePatterns := make([]proxy.NoisePattern, len(cfg.NoisePatterns))
	for i, p := range cfg.NoisePatterns {
		noisePatterns[i] = proxy.NoisePattern{ID: proxy.GenerateID(), Pattern: p.Pattern}
	}
	s.noise.SetEnabled(cfg.NoiseEnabled)
	s.noise.SetPatterns(noisePatterns)

	replaceRules := make([]proxy.MatchReplaceRule, len(cfg.ReplaceRules))
	for i, r := range cfg.ReplaceRules {
		replaceRules[i] = proxy.MatchReplaceRule{ID: proxy.GenerateID(), Target: r.Target, MatchType: r.MatchType, Match: r.Match, Replace: r.Replace}
	}
	s.replace.SetEnabled(cfg.ReplaceEnabled)
	s.replace.SetRules(replaceRules)

	customItems := make([]proxy.CustomAddition, len(cfg.CustomDataItems))
	for i, item := range cfg.CustomDataItems {
		customItems[i] = proxy.CustomAddition{ID: proxy.GenerateID(), Type: item.Type, Name: item.Name, Value: item.Value}
	}
	s.customData.SetEnabled(cfg.CustomDataEnabled)
	s.customData.SetItems(customItems)

	// Apply notes: clear existing, then insert from config with validation.
	if s.noteStore != nil {
		_ = s.noteStore.ClearAll()
		for _, n := range cfg.Notes {
			host, content, author := n.Host, n.Content, n.Author
			if len(host) > 253 {
				host = host[:253]
			}
			if len(content) > 65536 {
				content = content[:65536]
			}
			if len(author) > 64 {
				author = author[:64]
			}
			if host == "" || content == "" {
				continue
			}
			id, err := uuid.GenerateUUID()
			if err != nil {
				continue
			}
			_, _ = s.noteStore.CreateNote(id, host, content, author)
		}
	}

	s.mu.Lock()
	s.highlights = make(map[string]string)
	for k, v := range cfg.Highlights {
		s.highlights[k] = v
	}
	s.mu.Unlock()

	if len(cfg.RequestHistory) > 0 {
		items := make([]*proxy.CapturedRequest, len(cfg.RequestHistory))
		for i, r := range cfg.RequestHistory {
			ts, _ := time.Parse(time.RFC3339Nano, r.Timestamp)
			items[i] = &proxy.CapturedRequest{
				ID: r.ID, Seq: r.Seq, Timestamp: ts,
				Method: r.Method, URL: r.URL, Host: r.Host,
				StatusCode: r.StatusCode, ContentType: r.ContentType,
				Duration: time.Duration(r.DurationNs),
				ReqRaw:   r.ReqRaw, RespRaw: r.RespRaw,
			}
		}
		s.store.LoadItems(items)
	} else {
		s.store.Clear()
	}

	var unknownPluginStates []string
	if s.pluginManager != nil {
		unknownPluginStates = s.pluginManager.ApplyProjectStates(decodedPluginStates)
	}

	resp := map[string]any{
		"listenerUrl":       cfg.ListenerURL,
		"teamToken":         cfg.TeamToken,
		"teamNickname":      nickname,
		"projectId":         cfg.ProjectID,
		"scopeEnabled":      cfg.ScopeEnabled,
		"scopeRules":        scopeRules,
		"noiseEnabled":      cfg.NoiseEnabled,
		"noisePatterns":     noisePatterns,
		"replaceEnabled":    cfg.ReplaceEnabled,
		"replaceRules":      replaceRules,
		"customDataEnabled": cfg.CustomDataEnabled,
		"customDataItems":   customItems,
		"historyRestored":   true,
	}
	if len(unknownPluginStates) > 0 {
		resp["unknownPluginStates"] = unknownPluginStates
	}
	return resp
}

// ---- Handlers ----

func (s *APIServer) handleListUserConfigs(w http.ResponseWriter, r *http.Request) {
	names, err := s.configStore.List("user")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.RLock()
	active := s.activeUserConfig
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"configs": names, "active": active})
}

func (s *APIServer) handleSaveUserConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string   `json:"name"`
		Theme      string   `json:"theme"`
		HiddenTabs []string `json:"hiddenTabs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := configstore.ValidateName(body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.RLock()
	cfg := userConfigFile{
		Version:             3,
		SOCKSHost:           s.settings.SOCKSHost,
		SOCKSPort:           s.settings.SOCKSPort,
		SOCKSUsername:       s.settings.SOCKSUsername,
		SOCKSPassword:       s.settings.SOCKSPassword,
		SOCKSDNS:            s.settings.SOCKSDNS,
		HTTP2Enabled:        s.settings.HTTP2Enabled,
		KeepAliveEnabled:    s.settings.KeepAliveEnabled,
		InterceptTimeout:    s.settings.InterceptTimeout,
		MaxRequests:         s.settings.MaxRequests,
		DisableUpdateChecks: s.settings.DisableUpdateChecks,
		Theme:               body.Theme,
		HiddenTabs:          body.HiddenTabs,
	}
	ghost := s.pendingUserPluginStates
	s.mu.RUnlock()

	var fresh map[string][]byte
	if s.pluginManager != nil {
		fresh = s.pluginManager.ExportUserStates()
	}
	cfg.PluginStates = encodePluginStates(mergePluginStates(ghost, fresh))

	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := s.configStore.Save("user", body.Name, data); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.mu.Lock()
	s.activeUserConfig = body.Name
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "name": body.Name})
}

func (s *APIServer) handleLoadUserConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	data, err := s.configStore.Load("user", name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var cfg userConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt config file")
		return
	}

	decodedPluginStates := decodePluginStates(cfg.PluginStates)

	s.mu.Lock()
	s.settings.SOCKSHost = cfg.SOCKSHost
	s.settings.SOCKSPort = cfg.SOCKSPort
	s.settings.SOCKSUsername = cfg.SOCKSUsername
	s.settings.SOCKSPassword = cfg.SOCKSPassword
	s.settings.SOCKSDNS = cfg.SOCKSDNS
	s.settings.HTTP2Enabled = cfg.HTTP2Enabled
	s.settings.KeepAliveEnabled = cfg.KeepAliveEnabled
	s.settings.InterceptTimeout = cfg.InterceptTimeout
	if cfg.MaxRequests > 0 {
		s.settings.MaxRequests = cfg.MaxRequests
	}
	s.settings.DisableUpdateChecks = cfg.DisableUpdateChecks
	s.activeUserConfig = name
	s.pendingUserPluginStates = decodedPluginStates
	settings := s.settings
	s.mu.Unlock()

	// Apply side effects.
	if s.transport != nil {
		s.transport.SetHTTP2(cfg.HTTP2Enabled)
		s.transport.SetKeepAlive(cfg.KeepAliveEnabled)
		s.transport.SetSOCKS(cfg.SOCKSHost, cfg.SOCKSPort, cfg.SOCKSUsername, cfg.SOCKSPassword, cfg.SOCKSDNS)
	}
	if s.intercept != nil && cfg.InterceptTimeout > 0 {
		s.intercept.SetTimeout(time.Duration(cfg.InterceptTimeout) * time.Second)
	}
	if s.store != nil && cfg.MaxRequests > 0 {
		s.store.SetMaxSize(cfg.MaxRequests)
	}

	var unknownPluginStates []string
	if s.pluginManager != nil {
		unknownPluginStates = s.pluginManager.ApplyUserStates(decodedPluginStates)
	}

	// Return settings + theme so frontend can update.
	resp := struct {
		Settings
		Theme               string   `json:"theme"`
		HiddenTabs          []string `json:"hiddenTabs,omitempty"`
		UnknownPluginStates []string `json:"unknownPluginStates,omitempty"`
	}{
		Settings:            settings,
		Theme:               cfg.Theme,
		HiddenTabs:          cfg.HiddenTabs,
		UnknownPluginStates: unknownPluginStates,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleDeleteUserConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.configStore.Delete("user", name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.mu.Lock()
	if s.activeUserConfig == name {
		s.activeUserConfig = ""
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Project Config Handlers ---

func (s *APIServer) handleListProjectConfigs(w http.ResponseWriter, r *http.Request) {
	names, err := s.configStore.List("project")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.RLock()
	active := s.activeProjectConfig
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"configs": names, "active": active})
}

func (s *APIServer) handleSaveProjectConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := configstore.ValidateName(body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg := s.buildProjectConfig()
	gzBytes, err := gzipJSON(cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.configStore.SaveGzip("project", body.Name, gzBytes); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.mu.Lock()
	s.activeProjectConfig = body.Name
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "name": body.Name})
}

func (s *APIServer) handleLoadProjectConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	data, err := s.configStore.LoadAny("project", name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	data, isLegacy, err := gunzipIfNeeded(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to decompress config")
		return
	}

	var cfg projectConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt config file")
		return
	}

	// Convert legacy .json config to .joro format.
	if isLegacy {
		if gzBytes, err := gzipJSON(cfg); err == nil {
			_ = s.configStore.SaveGzip("project", name, gzBytes)
		}
	}

	resp := s.applyProjectConfig(&cfg, name, false)
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleDeleteProjectConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.configStore.DeleteAll("project", name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.mu.Lock()
	if s.activeProjectConfig == name {
		s.activeProjectConfig = ""
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Shared project config export/import + collaboration apply ---

// sharedConfigPayload is the 3-field unit exchanged by the collaboration flow
// (Feature B): scope + match&replace + custom data only.
type sharedConfigPayload struct {
	ScopeEnabled      bool                 `json:"scopeEnabled"`
	ScopeRules        []projectScopeRule   `json:"scopeRules"`
	ReplaceEnabled    bool                 `json:"replaceEnabled"`
	ReplaceRules      []projectReplaceRule `json:"replaceRules"`
	CustomDataEnabled bool                 `json:"customDataEnabled"`
	CustomDataItems   []projectCustomItem  `json:"customDataItems"`
}

// handleExportProjectConfig returns the current live project config as a
// base64(gzipped) blob, ready to publish to the team server (Feature A).
func (s *APIServer) handleExportProjectConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.buildProjectConfig()
	gzBytes, err := gzipJSON(cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"config":    base64.StdEncoding.EncodeToString(gzBytes),
		"projectId": cfg.ProjectID,
	})
}

// handleImportSharedConfig writes a published project config blob as a NEW local
// project file and loads it (Feature A). It preserves the importer's own team
// nickname and refuses to clobber an existing local project of the same name.
func (s *APIServer) handleImportSharedConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string `json:"name"`
		Config string `json:"config"` // base64(gzipped projectConfigFile)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := configstore.ValidateName(body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Refuse to overwrite an existing local project.
	if existing, err := s.configStore.List("project"); err == nil {
		for _, n := range existing {
			if n == body.Name {
				writeError(w, http.StatusConflict, "a project named "+body.Name+" already exists; choose another name")
				return
			}
		}
	}

	gzBytes, err := base64.StdEncoding.DecodeString(body.Config)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid config base64")
		return
	}
	jsonData, _, err := gunzipIfNeeded(gzBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to decompress config")
		return
	}
	var cfg projectConfigFile
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "corrupt config blob")
		return
	}

	if err := s.configStore.SaveGzip("project", body.Name, gzBytes); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := s.applyProjectConfig(&cfg, body.Name, true) // preserve importer's nickname
	writeJSON(w, http.StatusOK, resp)
}

// handleApplySharedConfig applies a 3-field shared config (scope/replace/custom
// data) to live state in "replace" or "merge" mode (Feature B). It never touches
// history, notes, highlights, team settings, or the project file.
func (s *APIServer) handleApplySharedConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config sharedConfigPayload `json:"config"`
		Mode   string              `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	merge := body.Mode == "merge"

	// Scope.
	scopeRules := make([]proxy.ScopeRule, 0, len(body.Config.ScopeRules))
	if merge {
		scopeRules = append(scopeRules, s.scope.Rules()...)
	}
	for _, r := range body.Config.ScopeRules {
		if merge && containsScopeRule(scopeRules, r) {
			continue
		}
		scopeRules = append(scopeRules, proxy.ScopeRule{
			ID: proxy.GenerateID(), Pattern: r.Pattern, Methods: r.Methods, Path: r.Path, Include: r.Include,
		})
	}
	s.scope.SetRules(scopeRules)
	s.scope.SetEnabled(body.Config.ScopeEnabled || (merge && s.scope.IsEnabled()))

	// Match & replace.
	replaceRules := make([]proxy.MatchReplaceRule, 0, len(body.Config.ReplaceRules))
	if merge {
		replaceRules = append(replaceRules, s.replace.Rules()...)
	}
	for _, r := range body.Config.ReplaceRules {
		if merge && containsReplaceRule(replaceRules, r) {
			continue
		}
		replaceRules = append(replaceRules, proxy.MatchReplaceRule{
			ID: proxy.GenerateID(), Target: r.Target, MatchType: r.MatchType, Match: r.Match, Replace: r.Replace,
		})
	}
	s.replace.SetRules(replaceRules)
	s.replace.SetEnabled(body.Config.ReplaceEnabled || (merge && s.replace.IsEnabled()))

	// Custom data.
	customItems := make([]proxy.CustomAddition, 0, len(body.Config.CustomDataItems))
	if merge {
		customItems = append(customItems, s.customData.Items()...)
	}
	for _, it := range body.Config.CustomDataItems {
		if merge && containsCustomItem(customItems, it) {
			continue
		}
		customItems = append(customItems, proxy.CustomAddition{
			ID: proxy.GenerateID(), Type: it.Type, Name: it.Name, Value: it.Value,
		})
	}
	s.customData.SetItems(customItems)
	s.customData.SetEnabled(body.Config.CustomDataEnabled || (merge && s.customData.IsEnabled()))

	writeJSON(w, http.StatusOK, map[string]any{
		"scopeEnabled":      s.scope.IsEnabled(),
		"scopeRules":        s.scope.Rules(),
		"replaceEnabled":    s.replace.IsEnabled(),
		"replaceRules":      s.replace.Rules(),
		"customDataEnabled": s.customData.IsEnabled(),
		"customDataItems":   s.customData.Items(),
	})
}

func containsScopeRule(rules []proxy.ScopeRule, r projectScopeRule) bool {
	key := r.Pattern + "|" + r.Path + "|" + fmt.Sprint(r.Include) + "|" + fmt.Sprint(r.Methods)
	for _, x := range rules {
		if x.Pattern+"|"+x.Path+"|"+fmt.Sprint(x.Include)+"|"+fmt.Sprint(x.Methods) == key {
			return true
		}
	}
	return false
}

func containsReplaceRule(rules []proxy.MatchReplaceRule, r projectReplaceRule) bool {
	for _, x := range rules {
		if x.Target == r.Target && x.MatchType == r.MatchType && x.Match == r.Match && x.Replace == r.Replace {
			return true
		}
	}
	return false
}

func containsCustomItem(items []proxy.CustomAddition, it projectCustomItem) bool {
	for _, x := range items {
		if x.Type == it.Type && x.Name == it.Name && x.Value == it.Value {
			return true
		}
	}
	return false
}
