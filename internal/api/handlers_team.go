package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/team"
	"github.com/hashicorp/go-uuid"
)

// postSystemChat persists a system chat message (author "*") and broadcasts it,
// so connection/rename events become part of the durable session log.
func (s *APIServer) postSystemChat(text string) {
	if s.teamStore == nil {
		return
	}
	id, err := uuid.GenerateUUID()
	if err != nil {
		return
	}
	msg, err := s.teamStore.CreateMessage(id, "*", text, "", "")
	if err != nil {
		return
	}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.chat", Data: msg}
}

// --- Teamserver-side handlers (direct DB access) ---

func (s *APIServer) handleListChatMessages(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}

	items, total, err := s.teamStore.ListMessages(offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []team.ChatMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleCreateChatMessage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text    string `json:"text"`
		RefType string `json:"refType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Text == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}
	// Only "action" (/me, /slap) may be set by clients; artifact chip types
	// (flagged/collab/config) are set server-side and must not be forgeable.
	if body.RefType != "" && body.RefType != "action" {
		body.RefType = ""
	}

	author := team.NicknameFromContext(r.Context())

	id, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	msg, err := s.teamStore.CreateMessage(id, author, body.Text, "", body.RefType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.hub.Broadcast() <- event.WSEvent{Type: "team.chat", Data: msg}
	writeJSON(w, http.StatusCreated, msg)
}

func (s *APIServer) handleListActiveUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.hub.ActiveUsersDetailed())
}

var validPresenceStatus = map[string]bool{"online": true, "away": true, "dnd": true, "offline": true}

func (s *APIServer) handleTeamPresence(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status    string `json:"status"`
		ProjectID string `json:"projectId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !validPresenceStatus[body.Status] {
		body.Status = "online"
	}
	nickname := team.NicknameFromContext(r.Context())
	s.hub.SetPresenceMeta(nickname, body.Status, body.ProjectID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *APIServer) handleTeamRename(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldNickname string `json:"oldNickname"`
		NewNickname string `json:"newNickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.OldNickname == "" || body.NewNickname == "" {
		writeError(w, http.StatusBadRequest, "oldNickname and newNickname are required")
		return
	}
	if body.OldNickname == body.NewNickname {
		writeJSON(w, http.StatusOK, map[string]string{"status": "unchanged"})
		return
	}

	// Prevent a user from renaming a different user.
	if caller := team.NicknameFromContext(r.Context()); caller != body.OldNickname {
		writeError(w, http.StatusForbidden, "cannot rename a different user")
		return
	}

	ok, err := s.hub.Rename(body.OldNickname, body.NewNickname)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not connected")
		return
	}
	s.postSystemChat(body.OldNickname + " changed nickname to " + body.NewNickname)
	writeJSON(w, http.StatusOK, map[string]string{"status": "renamed"})
}

func (s *APIServer) handleListTeamNoteHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.teamStore.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hosts == nil {
		hosts = []string{}
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *APIServer) handleListTeamNotes(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host") // empty host = general (host-less) notes
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	items, total, err := s.teamStore.ListNotes(host, offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []team.Note{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleCreateTeamNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string `json:"host"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}

	author := team.NicknameFromContext(r.Context())

	id, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	note, err := s.teamStore.CreateNote(id, body.Host, body.Content, author)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.hub.Broadcast() <- event.WSEvent{Type: "team.note", Data: note}
	writeJSON(w, http.StatusCreated, note)
}

func (s *APIServer) handleUpdateTeamNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}

	note, err := s.teamStore.GetNote(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "note not found")
		return
	}
	// Soft ownership: only the author may edit their note.
	if note.Author != team.NicknameFromContext(r.Context()) {
		writeError(w, http.StatusForbidden, "only the author can edit this note")
		return
	}

	updated, err := s.teamStore.UpdateNote(id, body.Content)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.note", Data: updated}
	writeJSON(w, http.StatusOK, updated)
}

func (s *APIServer) handleDeleteTeamNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	note, err := s.teamStore.GetNote(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "note not found")
		return
	}
	// Soft ownership: only the author may delete their note.
	if note.Author != team.NicknameFromContext(r.Context()) {
		writeError(w, http.StatusForbidden, "only the author can delete this note")
		return
	}

	if err := s.teamStore.DeleteNote(id); err != nil {
		writeError(w, http.StatusNotFound, "note not found")
		return
	}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.note.deleted", Data: map[string]string{"id": id}}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// maxFlaggedRespBytes caps the stored response of a flagged request to keep the
// shared DB from bloating on large binary downloads.
const maxFlaggedRespBytes = 256 * 1024

func (s *APIServer) handleListFlagged(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	items, total, err := s.teamStore.ListFlagged(offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []team.FlaggedSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleCreateFlagged(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string `json:"host"`
		Method  string `json:"method"`
		URL     string `json:"url"`
		Status  int    `json:"status"`
		ReqRaw  string `json:"reqRaw"`
		RespRaw string `json:"respRaw"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.URL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}

	reqRaw, err := base64.StdEncoding.DecodeString(body.ReqRaw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid reqRaw base64")
		return
	}
	respRaw, err := base64.StdEncoding.DecodeString(body.RespRaw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid respRaw base64")
		return
	}
	truncated := false
	if len(respRaw) > maxFlaggedRespBytes {
		respRaw = respRaw[:maxFlaggedRespBytes]
		truncated = true
	}

	author := team.NicknameFromContext(r.Context())

	id, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	artifact, err := s.teamStore.CreateFlagged(id, body.Host, body.Method, body.URL, body.Status, reqRaw, respRaw, truncated, body.Note, author)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Drop a referencing chat message so the flag surfaces in the conversation.
	text := "🚩 " + body.Method + " " + body.URL
	if body.Note != "" {
		text = "🚩 " + body.Note
	}
	chatID, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	chatMsg, err := s.teamStore.CreateMessage(chatID, author, text, artifact.ID, "flagged")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.hub.Broadcast() <- event.WSEvent{Type: "team.flagged", Data: artifact.FlaggedSummary}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.chat", Data: chatMsg}
	writeJSON(w, http.StatusCreated, artifact.FlaggedSummary)
}

func (s *APIServer) handleGetFlagged(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, err := s.teamStore.GetFlagged(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "flagged request not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":        f.ID,
		"host":      f.Host,
		"method":    f.Method,
		"url":       f.URL,
		"status":    f.Status,
		"truncated": f.Truncated,
		"note":      f.Note,
		"author":    f.Author,
		"createdAt": f.CreatedAt,
		"reqRaw":    base64.StdEncoding.EncodeToString(f.ReqRaw),
		"respRaw":   base64.StdEncoding.EncodeToString(f.RespRaw),
	})
}

func (s *APIServer) handleDeleteFlagged(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.teamStore.DeleteFlagged(id); err != nil {
		writeError(w, http.StatusNotFound, "flagged request not found")
		return
	}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.flagged.deleted", Data: map[string]string{"id": id}}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// --- Shared configs (Feature A) ---

func (s *APIServer) handleListSharedConfigs(w http.ResponseWriter, r *http.Request) {
	items, err := s.teamStore.ListSharedConfigs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []team.SharedConfig{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *APIServer) handleCreateSharedConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		ProjectID string `json:"projectId"`
		Config    string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Name == "" || body.Config == "" {
		writeError(w, http.StatusBadRequest, "name and config are required")
		return
	}

	author := team.NicknameFromContext(r.Context())
	id, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cfg, err := s.teamStore.CreateSharedConfig(id, body.Name, body.ProjectID, author, body.Config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	chatID, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	chatMsg, err := s.teamStore.CreateMessage(chatID, author, "📦 published config '"+body.Name+"'", cfg.ID, "config")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	summary := team.SharedConfig{ID: cfg.ID, Name: cfg.Name, ProjectID: cfg.ProjectID, Author: cfg.Author, CreatedAt: cfg.CreatedAt}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.config", Data: summary}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.chat", Data: chatMsg}
	writeJSON(w, http.StatusCreated, summary)
}

func (s *APIServer) handleGetSharedConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.teamStore.GetSharedConfig(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "shared config not found")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *APIServer) handleDeleteSharedConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.teamStore.DeleteSharedConfig(id); err != nil {
		writeError(w, http.StatusNotFound, "shared config not found")
		return
	}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.config.deleted", Data: map[string]string{"id": id}}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// --- Collaboration requests (Feature B) ---

func (s *APIServer) handleCreateCollab(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProjectID string `json:"projectId"`
		Note      string `json:"note"`
		Config    string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Config == "" {
		writeError(w, http.StatusBadRequest, "config is required")
		return
	}

	requestor := team.NicknameFromContext(r.Context())
	id, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	req, err := s.teamStore.CreateCollabRequest(id, requestor, body.ProjectID, body.Note, body.Config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	text := "🤝 " + requestor + " is requesting collaboration"
	if body.ProjectID != "" {
		text += " on " + body.ProjectID
	}
	if body.Note != "" {
		text += ": " + body.Note
	}
	chatID, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	chatMsg, err := s.teamStore.CreateMessage(chatID, requestor, text, req.ID, "collab")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	summary := team.CollabRequest{ID: req.ID, Requestor: req.Requestor, ProjectID: req.ProjectID, Note: req.Note, Status: req.Status, CreatedAt: req.CreatedAt}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.collab.request", Data: summary}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.chat", Data: chatMsg}
	writeJSON(w, http.StatusCreated, summary)
}

func (s *APIServer) handleGetCollab(w http.ResponseWriter, r *http.Request) {
	req, err := s.teamStore.GetCollabRequest(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "collaboration request not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *APIServer) handleAcceptCollab(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, err := s.teamStore.GetCollabRequest(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "collaboration request not found")
		return
	}
	acceptor := team.NicknameFromContext(r.Context())

	chatID, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	chatMsg, err := s.teamStore.CreateMessage(chatID, acceptor, acceptor+" joined "+req.Requestor+"'s collaboration", "", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.collab.accepted", Data: map[string]string{"id": id, "acceptedBy": acceptor}}
	s.hub.Broadcast() <- event.WSEvent{Type: "team.chat", Data: chatMsg}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// --- Proxy-side handlers (forward to teamserver via proxyToListener) ---

func (s *APIServer) handleProxyTeamChat(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamUsers(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamPresence(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamNotes(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamFlagged(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamConfigs(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamCollab(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}
