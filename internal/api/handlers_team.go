package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/team"
	"github.com/hashicorp/go-uuid"
)

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
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Text == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}

	author := team.NicknameFromContext(r.Context())

	id, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	msg, err := s.teamStore.CreateMessage(id, author, body.Text)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.hub.Broadcast() <- event.WSEvent{Type: "team.chat", Data: msg}
	writeJSON(w, http.StatusCreated, msg)
}

func (s *APIServer) handleListActiveUsers(w http.ResponseWriter, r *http.Request) {
	users := s.hub.ActiveUsers()
	writeJSON(w, http.StatusOK, users)
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
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "host parameter required")
		return
	}
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
	if body.Host == "" || body.Content == "" {
		writeError(w, http.StatusBadRequest, "host and content are required")
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

func (s *APIServer) handleDeleteTeamNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.teamStore.DeleteNote(id); err != nil {
		writeError(w, http.StatusNotFound, "note not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// --- Proxy-side handlers (forward to teamserver via proxyToListener) ---

func (s *APIServer) handleProxyTeamChat(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamUsers(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}

func (s *APIServer) handleProxyTeamNotes(w http.ResponseWriter, r *http.Request) {
	s.proxyToListener(w, r)
}
