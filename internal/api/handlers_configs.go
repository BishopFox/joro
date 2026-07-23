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
	AutoSave          bool                     `json:"autoSave"`
	SaveHistory       bool                     `json:"saveHistory"`
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
// (shared by save and export). The autoSave/saveHistory prefs are baked into the
// file for portability; when saveHistory is false the request history is omitted.
func (s *APIServer) buildProjectConfig(autoSave, saveHistory bool) projectConfigFile {
	s.mu.RLock()
	listenerURL := s.settings.ListenerURL
	teamToken := s.settings.TeamToken
	teamNickname := s.settings.TeamNickname
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

	var pReqs []projectCapturedRequest
	if saveHistory {
		allReqs := s.store.All()
		pReqs = make([]projectCapturedRequest, len(allReqs))
		for i, r := range allReqs {
			pReqs[i] = projectCapturedRequest{
				ID: r.ID, Seq: r.Seq, Timestamp: r.Timestamp.Format(time.RFC3339Nano),
				Method: r.Method, URL: r.URL, Host: r.Host,
				StatusCode: r.StatusCode, ContentType: r.ContentType,
				DurationNs: int64(r.Duration), ReqRaw: r.ReqRaw, RespRaw: r.RespRaw,
			}
		}
	}

	var projectFresh map[string][]byte
	if s.pluginManager != nil {
		projectFresh = s.pluginManager.ExportProjectStates()
	}

	return projectConfigFile{
		Version:           4,
		AutoSave:          autoSave,
		SaveHistory:       saveHistory,
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

// normalizeProjectConfig applies defaults for fields added after a config file
// was written. Pre-v4 files have no autoSave/saveHistory, which must both
// default to true rather than the Go bool zero value (false).
func normalizeProjectConfig(cfg *projectConfigFile) {
	if cfg.Version < 4 {
		cfg.AutoSave = true
		cfg.SaveHistory = true
	}
}

// projectMeta is the per-project metadata surfaced by the project browser and
// persisted in a lightweight <name>.meta.json sidecar (so counts/prefs can be
// read/toggled without decompressing the potentially huge .joro).
type projectMeta struct {
	Name         string `json:"name"`
	SavedAt      string `json:"savedAt"`
	SizeBytes    int64  `json:"sizeBytes"`
	RequestCount int    `json:"requestCount"`
	NoteCount    int    `json:"noteCount"`
	AutoSave     bool   `json:"autoSave"`
	SaveHistory  bool   `json:"saveHistory"`
	Active       bool   `json:"active"`
}

// defaultProjectMeta returns metadata with prefs defaulted on (used when no
// sidecar exists yet).
func defaultProjectMeta(name string) projectMeta {
	return projectMeta{Name: name, AutoSave: true, SaveHistory: true}
}

// readProjectMeta loads a project's sidecar. The bool reports whether a sidecar
// was found (false → defaults returned).
func (s *APIServer) readProjectMeta(name string) (projectMeta, bool) {
	data, err := s.configStore.LoadSidecar("project", name)
	if err != nil {
		return defaultProjectMeta(name), false
	}
	var m projectMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return defaultProjectMeta(name), false
	}
	m.Name = name
	return m, true
}

// writeProjectMeta persists a project's sidecar (best-effort).
func (s *APIServer) writeProjectMeta(name string, m projectMeta) {
	m.Name = name
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	_ = s.configStore.SaveSidecar("project", name, data)
}

// backfillProjectMeta reconstructs a sidecar from the .joro (used for legacy or
// pre-feature files that have none) by decompressing once and caching the result.
func (s *APIServer) backfillProjectMeta(name string) projectMeta {
	m := defaultProjectMeta(name)
	data, err := s.configStore.LoadAny("project", name)
	if err != nil {
		return m
	}
	data, _, err = gunzipIfNeeded(data)
	if err != nil {
		return m
	}
	var cfg projectConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return m
	}
	normalizeProjectConfig(&cfg)
	m.RequestCount = len(cfg.RequestHistory)
	for _, n := range cfg.Notes {
		if n.Content != "" {
			m.NoteCount++
		}
	}
	m.AutoSave = cfg.AutoSave
	m.SaveHistory = cfg.SaveHistory
	s.writeProjectMeta(name, m)
	return m
}

// resolveProjectPrefs returns a project's autoSave/saveHistory preferences from
// its sidecar (both default true for an unnamed/scratch or sidecar-less project).
func (s *APIServer) resolveProjectPrefs(name string) (autoSave, saveHistory bool) {
	if name == "" {
		return true, true
	}
	m, ok := s.readProjectMeta(name)
	if !ok {
		m = s.backfillProjectMeta(name)
	}
	return m.AutoSave, m.SaveHistory
}

// setActiveProject records the active project name (in-memory only; not
// persisted across restarts).
func (s *APIServer) setActiveProject(name string) {
	s.mu.Lock()
	s.activeProjectConfig = name
	s.mu.Unlock()
}

// liveStateSignature is a cheap fingerprint of the mutable project state used by
// the auto-save loop to skip ticks when nothing changed. It counts rather than
// diffs, so a same-count in-place edit between ticks is not detected.
func (s *APIServer) liveStateSignature() string {
	reqCount, lastSeq := 0, 0
	if s.store != nil {
		reqCount = s.store.Count()
		lastSeq = s.store.LastSeq()
	}
	noteCount := 0
	var maxNoteUpdate int64
	if s.noteStore != nil {
		if all, err := s.noteStore.LoadAll(); err == nil {
			noteCount = len(all)
			for _, n := range all {
				if u := n.UpdatedAt.UnixNano(); u > maxNoteUpdate {
					maxNoteUpdate = u
				}
			}
		}
	}
	s.mu.RLock()
	hlCount := len(s.highlights)
	s.mu.RUnlock()
	return fmt.Sprintf("r%d/s%d/n%d/u%d/h%d/sc%d/rp%d/cd%d/no%d",
		reqCount, lastSeq, noteCount, maxNoteUpdate, hlCount,
		len(s.scope.Rules()), len(s.replace.Rules()),
		len(s.customData.Items()), len(s.noise.Patterns()))
}

// saveProject snapshots live state to the named project's .joro (respecting its
// saveHistory pref), refreshes its sidecar, and marks it active. Shared by the
// manual save handler, the switch handler, and the auto-save loop.
func (s *APIServer) saveProject(name string) error {
	autoSave, saveHistory := s.resolveProjectPrefs(name)
	cfg := s.buildProjectConfig(autoSave, saveHistory)
	gzBytes, err := gzipJSON(cfg)
	if err != nil {
		return err
	}
	if err := s.configStore.SaveGzip("project", name, gzBytes); err != nil {
		return err
	}
	s.setActiveProject(name)

	noteCount := 0
	if s.noteStore != nil {
		if all, err := s.noteStore.LoadAll(); err == nil {
			noteCount = len(all)
		}
	}
	s.writeProjectMeta(name, projectMeta{
		RequestCount: len(cfg.RequestHistory),
		NoteCount:    noteCount,
		AutoSave:     autoSave,
		SaveHistory:  saveHistory,
	})

	sig := s.liveStateSignature()
	s.mu.Lock()
	s.lastSaveSig = sig
	s.mu.Unlock()
	return nil
}

// resetLiveProjectState clears the live project state to a fresh-session
// baseline: no scope/replace/customdata rules (disabled), default noise
// patterns, empty notes/highlights/history, cleared plugin project state, and
// cleared team-server settings.
func (s *APIServer) resetLiveProjectState() {
	s.scope.SetEnabled(false)
	s.scope.SetRules(nil)
	def := proxy.NewNoiseFilter()
	s.noise.SetEnabled(def.IsEnabled())
	s.noise.SetPatterns(def.Patterns())
	s.replace.SetEnabled(false)
	s.replace.SetRules(nil)
	s.customData.SetEnabled(false)
	s.customData.SetItems(nil)
	if s.noteStore != nil {
		_ = s.noteStore.ClearAll()
	}
	s.store.Clear()

	s.mu.Lock()
	s.highlights = make(map[string]string)
	s.pendingProjectPluginStates = nil
	teamChanged := s.settings.ListenerURL != "" || s.settings.TeamToken != "" || s.settings.TeamNickname != ""
	s.settings.ListenerURL = ""
	s.settings.TeamToken = ""
	s.settings.TeamNickname = ""
	s.mu.Unlock()

	if teamChanged && s.listenerRelay != nil {
		s.listenerRelay.Update("", "", "")
	}
	if s.pluginManager != nil {
		s.pluginManager.ApplyProjectStates(nil)
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
			if content == "" {
				continue // host may be empty (general notes); content is required
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

	// Refresh the sidecar so the loaded project's counts show without decompressing
	// the .joro again. An existing sidecar's prefs win over the .joro's copy (the
	// sidecar is authoritative locally); the .joro seeds them only on first load.
	noteCount := 0
	for _, n := range cfg.Notes {
		if n.Content != "" {
			noteCount++
		}
	}
	autoSave, saveHistory := cfg.AutoSave, cfg.SaveHistory
	if existing, ok := s.readProjectMeta(name); ok {
		autoSave, saveHistory = existing.AutoSave, existing.SaveHistory
	}
	s.writeProjectMeta(name, projectMeta{
		RequestCount: len(cfg.RequestHistory),
		NoteCount:    noteCount,
		AutoSave:     autoSave,
		SaveHistory:  saveHistory,
	})

	// Record the post-load signature so the auto-save loop treats a freshly
	// loaded project as clean.
	sig := s.liveStateSignature()
	s.mu.Lock()
	s.lastSaveSig = sig
	s.mu.Unlock()

	resp := map[string]any{
		"listenerUrl":       cfg.ListenerURL,
		"teamToken":         cfg.TeamToken,
		"teamNickname":      nickname,
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

	projects := make([]projectMeta, 0, len(names))
	for _, n := range names {
		m, ok := s.readProjectMeta(n)
		if !ok {
			m = s.backfillProjectMeta(n) // legacy/pre-feature file: build sidecar once
		}
		// Filesystem is authoritative for size + last-saved time.
		if fi, statErr := s.configStore.Stat("project", n); statErr == nil {
			m.SizeBytes = fi.Size()
			m.SavedAt = fi.ModTime().UTC().Format(time.RFC3339)
		}
		m.Name = n
		m.Active = n == active
		projects = append(projects, m)
	}

	writeJSON(w, http.StatusOK, map[string]any{"configs": names, "active": active, "projects": projects})
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

	if err := s.saveProject(body.Name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

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
	normalizeProjectConfig(&cfg)

	// Convert legacy .json config to .joro format.
	if isLegacy {
		if gzBytes, err := gzipJSON(cfg); err == nil {
			_ = s.configStore.SaveGzip("project", name, gzBytes)
		}
	}

	resp := s.applyProjectConfig(&cfg, name, false)
	writeJSON(w, http.StatusOK, resp)
}

// handleSwitchProject saves the outgoing project (respecting its autoSave pref or
// an explicit action) then loads the target — the atomic backend of the header
// project switcher.
func (s *APIServer) handleSwitchProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          string `json:"name"`
		Action        string `json:"action"`
		SaveScratchAs string `json:"saveScratchAs"`
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
	active := s.activeProjectConfig
	s.mu.RUnlock()

	autoSaved := ""
	switch {
	case body.SaveScratchAs != "":
		// Name and persist the current scratch (or active) session before leaving.
		if err := configstore.ValidateName(body.SaveScratchAs); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if existing, err := s.configStore.List("project"); err == nil {
			for _, n := range existing {
				if n == body.SaveScratchAs {
					writeError(w, http.StatusConflict, "a project named "+body.SaveScratchAs+" already exists; choose another name")
					return
				}
			}
		}
		if err := s.saveProject(body.SaveScratchAs); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		autoSaved = body.SaveScratchAs
	case active != "":
		autoSave, _ := s.resolveProjectPrefs(active)
		shouldSave := body.Action == "save" || (body.Action != "discard" && autoSave)
		if shouldSave {
			if err := s.saveProject(active); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			autoSaved = active
		}
	}

	// Load the target project.
	data, err := s.configStore.LoadAny("project", body.Name)
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
	normalizeProjectConfig(&cfg)
	if isLegacy {
		if gzBytes, err := gzipJSON(cfg); err == nil {
			_ = s.configStore.SaveGzip("project", body.Name, gzBytes)
		}
	}

	resp := s.applyProjectConfig(&cfg, body.Name, false)
	if autoSaved != "" {
		resp["autoSaved"] = autoSaved
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSetProjectPrefs updates a project's autoSave/saveHistory preferences in
// its sidecar only (no .joro decompress).
func (s *APIServer) handleSetProjectPrefs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		AutoSave    *bool  `json:"autoSave"`
		SaveHistory *bool  `json:"saveHistory"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := configstore.ValidateName(body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, statErr := s.configStore.Stat("project", body.Name); statErr != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}

	m, ok := s.readProjectMeta(body.Name)
	if !ok {
		m = s.backfillProjectMeta(body.Name)
	}
	if body.AutoSave != nil {
		m.AutoSave = *body.AutoSave
	}
	if body.SaveHistory != nil {
		m.SaveHistory = *body.SaveHistory
	}
	s.writeProjectMeta(body.Name, m)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "autoSave": m.AutoSave, "saveHistory": m.SaveHistory})
}

// handleNewProject creates a NEW project (409 on name collision). With empty=false
// it snapshots the current session under the new name; with empty=true it saves the
// outgoing session (like a switch), then resets live state to a fresh baseline
// before saving the new project.
func (s *APIServer) handleNewProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          string `json:"name"`
		Empty         bool   `json:"empty"`
		Action        string `json:"action"`
		SaveScratchAs string `json:"saveScratchAs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := configstore.ValidateName(body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	existing, _ := s.configStore.List("project")
	nameTaken := func(n string) bool {
		for _, e := range existing {
			if e == n {
				return true
			}
		}
		return false
	}
	if nameTaken(body.Name) {
		writeError(w, http.StatusConflict, "a project named "+body.Name+" already exists; choose another name")
		return
	}

	if body.Empty {
		// Save the outgoing session first (same policy as a switch).
		s.mu.RLock()
		active := s.activeProjectConfig
		s.mu.RUnlock()
		switch {
		case body.SaveScratchAs != "":
			if err := configstore.ValidateName(body.SaveScratchAs); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if nameTaken(body.SaveScratchAs) {
				writeError(w, http.StatusConflict, "a project named "+body.SaveScratchAs+" already exists; choose another name")
				return
			}
			if err := s.saveProject(body.SaveScratchAs); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		case active != "":
			autoSave, _ := s.resolveProjectPrefs(active)
			if body.Action == "save" || (body.Action != "discard" && autoSave) {
				if err := s.saveProject(active); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
			}
		}
		s.resetLiveProjectState()
	}

	if err := s.saveProject(body.Name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "created", "name": body.Name, "empty": body.Empty})
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
	s.mu.RLock()
	active := s.activeProjectConfig
	s.mu.RUnlock()
	autoSave, saveHistory := s.resolveProjectPrefs(active)
	cfg := s.buildProjectConfig(autoSave, saveHistory)
	gzBytes, err := gzipJSON(cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"config": base64.StdEncoding.EncodeToString(gzBytes),
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
	normalizeProjectConfig(&cfg)

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
