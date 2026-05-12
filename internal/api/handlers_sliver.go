package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/BishopFox/joro/internal/sliver"
)

func (s *APIServer) handleSliverStatus(w http.ResponseWriter, r *http.Request) {
	lhost, lport, connected := s.sliverClient.ServerInfo()
	resp := map[string]any{"connected": connected}
	if connected {
		resp["lhost"] = lhost
		resp["lport"] = lport
		id, name, _ := s.sliverClient.GetActiveSession()
		if id != "" {
			resp["sessionId"] = id
			resp["sessionName"] = name
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleSliverConnect(w http.ResponseWriter, r *http.Request) {
	var cfg sliver.OperatorConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if cfg.LHost == "" || cfg.LPort == 0 {
		writeError(w, http.StatusBadRequest, "lhost and lport are required")
		return
	}
	if cfg.CACertificate == "" || cfg.Certificate == "" || cfg.PrivateKey == "" {
		writeError(w, http.StatusBadRequest, "ca_certificate, certificate, and private_key are required")
		return
	}

	if err := s.sliverClient.Connect(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"connected": true})
}

func (s *APIServer) handleSliverDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.sliverClient.Disconnect(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"connected": false})
}

func (s *APIServer) handleSliverSessions(w http.ResponseWriter, r *http.Request) {
	if !s.sliverClient.IsConnected() {
		writeError(w, http.StatusBadRequest, "not connected to Sliver teamserver")
		return
	}

	sessions, err := s.sliverClient.ListSessions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	beacons, err := s.sliverClient.ListBeacons(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": sessions,
		"beacons":  beacons,
	})
}

func (s *APIServer) handleSliverExecute(w http.ResponseWriter, r *http.Request) {
	if !s.sliverClient.IsConnected() {
		writeError(w, http.StatusBadRequest, "not connected to Sliver teamserver")
		return
	}

	var body struct {
		SessionID string   `json:"sessionId"`
		Command   string   `json:"command"`
		Args      []string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if body.SessionID == "" || body.Command == "" {
		writeError(w, http.StatusBadRequest, "sessionId and command are required")
		return
	}

	stdout, stderr, err := s.sliverClient.Execute(r.Context(), body.SessionID, body.Command, body.Args, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"output": stdout,
		"error":  stderr,
	})
}

// handleSliverCommand dispatches a sliver-client command.
func (s *APIServer) handleSliverCommand(w http.ResponseWriter, r *http.Request) {
	if !s.sliverClient.IsConnected() {
		writeError(w, http.StatusBadRequest, "not connected to Sliver teamserver")
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
		writeJSON(w, http.StatusOK, sliver.CommandResult{})
		return
	}

	result := s.sliverClient.Dispatch(r.Context(), body.Input)
	writeJSON(w, http.StatusOK, result)
}

// handleSliverDownload serves cached binary data (download, screenshot, procdump).
func (s *APIServer) handleSliverDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing download id")
		return
	}

	data, filename, ok := s.sliverClient.GetDownload(id)
	if !ok {
		writeError(w, http.StatusNotFound, "download not found or expired")
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// handleSliverUpload handles file upload to a remote target.
func (s *APIServer) handleSliverUpload(w http.ResponseWriter, r *http.Request) {
	if !s.sliverClient.IsConnected() {
		writeError(w, http.StatusBadRequest, "not connected to Sliver teamserver")
		return
	}

	sessionID, _, isBeacon := s.sliverClient.GetActiveSession()
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "no active session")
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

	path, err := s.sliverClient.Upload(r.Context(), sessionID, remotePath, data, header.Filename, isBeacon)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"path": path,
	})
}
