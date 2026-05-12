package api

import (
	"encoding/json"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/shell"
)

func (s *APIServer) handleExecute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target   string `json:"target"`
		Webshell string `json:"webshell"`
		AuthKey  string `json:"authKey"`
		Command  string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if body.Target == "" || body.Webshell == "" || body.AuthKey == "" || body.Command == "" {
		writeError(w, http.StatusBadRequest, "target, webshell, authKey, and command are required")
		return
	}

	client := proxy.NewHTTPClient("", s.transport)
	output, err := shell.ExecuteCommand(body.Target, body.Webshell, body.AuthKey, body.Command, client)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"output": "",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"output": output,
		"error":  "",
	})
}
