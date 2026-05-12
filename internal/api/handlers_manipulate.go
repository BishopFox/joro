package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/BishopFox/joro/internal/proxy"
)

type manipulateRequest struct {
	Raw                 string `json:"raw"`                           // raw HTTP request bytes, base64-encoded
	Scheme              string `json:"scheme"`                        // "http" or "https"
	Host                string `json:"host"`                          // host:port
	UpdateContentLength *bool  `json:"updateContentLength,omitempty"` // recalculate Content-Length
	FollowRedirects     *bool  `json:"followRedirects,omitempty"`     // follow HTTP redirects
	Decompress          *bool  `json:"decompress,omitempty"`          // unpack compressed responses
}

func (s *APIServer) handleManipulateSend(w http.ResponseWriter, r *http.Request) {
	var req manipulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	rawBytes, err := base64.StdEncoding.DecodeString(req.Raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid raw base64")
		return
	}

	if req.UpdateContentLength == nil || *req.UpdateContentLength {
		rawBytes = proxy.UpdateContentLength(rawBytes)
	}

	opts := proxy.SendOptions{
		FollowRedirects: req.FollowRedirects != nil && *req.FollowRedirects,
		Decompress:      req.Decompress == nil || *req.Decompress,
	}

	result, err := proxy.SendRawRequest(r.Context(), rawBytes, req.Scheme, req.Host, opts, s.transport)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sending request: %v", err))
		return
	}
	defer result.Response.Body.Close()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     result.Response.StatusCode,
		"durationMs": result.Duration.Milliseconds(),
		"rawResp":    base64.StdEncoding.EncodeToString(result.RawResp),
	})
}
