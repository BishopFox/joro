package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/BishopFox/joro/internal/notes"
	"github.com/hashicorp/go-uuid"
)

func (s *APIServer) handleListNoteHosts(w http.ResponseWriter, r *http.Request) {
	seen := make(map[string]struct{})

	// Hosts from proxy request history.
	if s.store != nil {
		for _, h := range s.store.Hosts() {
			seen[h] = struct{}{}
		}
	}

	// Hosts from notes DB.
	if s.noteStore != nil {
		dbHosts, err := s.noteStore.ListHosts()
		if err == nil {
			for _, h := range dbHosts {
				seen[h] = struct{}{}
			}
		}
	}

	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	writeJSON(w, http.StatusOK, hosts)
}

func (s *APIServer) handleListNotes(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host") // empty host = general (host-less) notes
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	items, total, err := s.noteStore.ListNotes(host, offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []notes.Note{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

func (s *APIServer) handleCreateNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string `json:"host"`
		Content string `json:"content"`
		Author  string `json:"author"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}
	if body.Author == "" {
		body.Author = "operator"
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	note, err := s.noteStore.CreateNote(id, body.Host, body.Content, body.Author)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, note)
}

func (s *APIServer) handleUpdateNote(w http.ResponseWriter, r *http.Request) {
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
	note, err := s.noteStore.UpdateNote(id, body.Content)
	if err != nil {
		writeError(w, http.StatusNotFound, "note not found")
		return
	}
	writeJSON(w, http.StatusOK, note)
}

func (s *APIServer) handleDeleteNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.noteStore.DeleteNote(id); err != nil {
		writeError(w, http.StatusNotFound, "note not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
