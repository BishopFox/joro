package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/BishopFox/joro/internal/mythic"
)

func (s *APIServer) handleMythicStatus(w http.ResponseWriter, r *http.Request) {
	url, connected := s.mythicClient.ServerInfo()
	resp := map[string]any{"connected": connected}
	if connected {
		resp["url"] = url
		id, name := s.mythicClient.GetActiveCallback()
		if id != 0 {
			resp["callbackId"] = id
			resp["callbackName"] = name
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleMythicConnect(w http.ResponseWriter, r *http.Request) {
	var cfg mythic.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if cfg.URL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	if cfg.APIToken == "" && (cfg.Username == "" || cfg.Password == "") {
		writeError(w, http.StatusBadRequest, "an API token, or a username and password, is required")
		return
	}

	if err := s.mythicClient.Connect(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"connected": true})
}

func (s *APIServer) handleMythicDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.mythicClient.Disconnect(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"connected": false})
}

func (s *APIServer) handleMythicCallbacks(w http.ResponseWriter, r *http.Request) {
	if !s.mythicClient.IsConnected() {
		writeError(w, http.StatusBadRequest, "not connected to Mythic")
		return
	}

	callbacks, err := s.mythicClient.ListCallbacks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"callbacks": callbacks})
}

// handleMythicCommand dispatches a mythic-client REPL command.
func (s *APIServer) handleMythicCommand(w http.ResponseWriter, r *http.Request) {
	if !s.mythicClient.IsConnected() {
		writeError(w, http.StatusBadRequest, "not connected to Mythic")
		return
	}

	var body struct {
		Input string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if body.Input == "" {
		writeJSON(w, http.StatusOK, mythic.CommandResult{})
		return
	}

	result := s.mythicClient.Dispatch(r.Context(), body.Input)
	writeJSON(w, http.StatusOK, result)
}

// handleMythicDownload serves cached binary data (files pulled from an agent).
func (s *APIServer) handleMythicDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing download id")
		return
	}

	data, filename, ok := s.mythicClient.GetDownload(id)
	if !ok {
		writeError(w, http.StatusNotFound, "download not found or expired")
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// handleMythicUpload registers a file with Mythic and issues an upload task to the
// active callback.
func (s *APIServer) handleMythicUpload(w http.ResponseWriter, r *http.Request) {
	if !s.mythicClient.IsConnected() {
		writeError(w, http.StatusBadRequest, "not connected to Mythic")
		return
	}

	callbackID, _ := s.mythicClient.GetActiveCallback()
	if callbackID == 0 {
		writeError(w, http.StatusBadRequest, "no active callback")
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	remotePath := r.FormValue("remotePath")
	if remotePath == "" {
		writeError(w, http.StatusBadRequest, "remotePath is required")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read file")
		return
	}

	path, err := s.mythicClient.RegisterAndUpload(r.Context(), callbackID, remotePath, header.Filename, data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}
