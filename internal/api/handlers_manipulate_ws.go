package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

// manipulateWSConnectRequest is the body of POST /manipulate/ws/connect.
type manipulateWSConnectRequest struct {
	Raw    string `json:"raw"`    // base64-encoded raw HTTP upgrade request
	Scheme string `json:"scheme"` // "ws" or "wss"
	Host   string `json:"host"`   // host[:port]
}

// manipulateWSSendRequest is the body of POST /manipulate/ws/{id}/send.
type manipulateWSSendRequest struct {
	Opcode  string `json:"opcode"`  // text|binary|ping|pong|close
	Payload string `json:"payload"` // base64-encoded
}

func (s *APIServer) handleManipulateWSConnect(w http.ResponseWriter, r *http.Request) {
	if s.wsManipulate == nil {
		writeError(w, http.StatusServiceUnavailable, "ws manipulation unavailable")
		return
	}

	var req manipulateWSConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	rawBytes, err := base64.StdEncoding.DecodeString(req.Raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid raw base64")
		return
	}

	sessID := "" // filled in after Dial; callbacks capture via closure
	var sessRef *proxy.ManipulateWSSession

	onFrame := func(direction string, opcode byte, payload []byte, ts time.Time) {
		if sessRef == nil {
			return
		}
		s.broadcastManipulateWSFrame(sessRef.ID, direction, opcode, payload, ts)
	}
	onClose := func(reason string) {
		if sessRef == nil {
			return
		}
		s.hub.Broadcast() <- event.WSEvent{
			Type: "manipulate.ws.closed",
			Data: map[string]any{
				"sessionId": sessRef.ID,
				"reason":    reason,
			},
		}
	}

	sess, rawResp, err := s.wsManipulate.Dial(rawBytes, req.Scheme, req.Host, onFrame, onClose)
	// Always return 200 so the client can inspect rawResp regardless of the
	// upgrade outcome. sessionId is empty on failure; error carries the reason.
	resp := map[string]any{
		"sessionId": "",
		"status":    0,
		"rawResp":   base64.StdEncoding.EncodeToString(rawResp),
		"error":     "",
	}
	if err != nil {
		resp["error"] = err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	sessRef = sess
	sessID = sess.ID
	resp["sessionId"] = sessID
	resp["status"] = http.StatusSwitchingProtocols
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleManipulateWSSend(w http.ResponseWriter, r *http.Request) {
	if s.wsManipulate == nil {
		writeError(w, http.StatusServiceUnavailable, "ws manipulation unavailable")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	var req manipulateWSSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	opcode, ok := proxy.OpcodeFromName(req.Opcode)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid opcode")
		return
	}

	var payload []byte
	if req.Payload != "" {
		b, err := base64.StdEncoding.DecodeString(req.Payload)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload base64")
			return
		}
		payload = b
	}

	if err := s.wsManipulate.Send(id, opcode, payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// If the user sent a close frame, also tear down the session.
	if opcode == 0x8 {
		s.wsManipulate.Close(id, "client closed")
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *APIServer) handleManipulateWSDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.wsManipulate == nil {
		writeError(w, http.StatusServiceUnavailable, "ws manipulation unavailable")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	if s.wsManipulate.Get(id) == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": errors.New("no such session").Error()})
		return
	}

	s.wsManipulate.Close(id, "client disconnected")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// broadcastManipulateWSFrame emits a manipulate.ws.frame event for one frame.
// Binary payloads are carried as base64; text payloads are carried the same
// way (isText is a display hint) so there's no encoding ambiguity on the wire.
func (s *APIServer) broadcastManipulateWSFrame(sessID, direction string, opcode byte, payload []byte, ts time.Time) {
	s.hub.Broadcast() <- event.WSEvent{
		Type: "manipulate.ws.frame",
		Data: map[string]any{
			"sessionId": sessID,
			"direction": direction,
			"opcode":    proxy.OpcodeName(opcode),
			"payload":   base64.StdEncoding.EncodeToString(payload),
			"isText":    opcode == 0x1,
			"size":      len(payload),
			"ts":        ts.UTC().Format(time.RFC3339Nano),
		},
	}
}
