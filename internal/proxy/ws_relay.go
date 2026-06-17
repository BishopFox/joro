package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

// CapturedWSMessage holds a captured WebSocket message.
type CapturedWSMessage struct {
	ID            string    `json:"id"`
	ConnectionID  string    `json:"connectionId"`
	Timestamp     time.Time `json:"timestamp"`
	Direction     string    `json:"direction"` // "client_to_server" or "server_to_client"
	Opcode        byte      `json:"opcode"`
	PayloadLength int       `json:"payloadLength"`
	Payload       string    `json:"payload"` // base64 for binary, raw for text
	Host          string    `json:"host"`
	URL           string    `json:"url"`
	IsText        bool      `json:"isText"`
}

// handleWSUpgradeHTTP handles WebSocket upgrades for plain HTTP proxy requests.
func (h *Handler) handleWSUpgradeHTTP(w http.ResponseWriter, r *http.Request, id string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Dial upstream.
	host := r.Host
	if r.URL.Port() == "" {
		host = r.Host + ":80"
	}

	var upstream net.Conn
	var err error
	if dialCtx := h.transport.SOCKSDialContext(); dialCtx != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		upstream, err = dialCtx(ctx, "tcp", host)
	} else {
		upstream, err = net.DialTimeout("tcp", host, 10*time.Second)
	}
	if err != nil {
		http.Error(w, "upstream dial error: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Write the upgrade request to upstream.
	raw, _ := httputil.DumpRequest(r, true)
	if _, err := upstream.Write(raw); err != nil {
		upstream.Close()
		http.Error(w, "upstream write error", http.StatusBadGateway)
		return
	}

	// Read upstream response.
	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		upstream.Close()
		http.Error(w, "upstream response error", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Write(w) //nolint:errcheck
		resp.Body.Close()
		upstream.Close()
		return
	}

	// Hijack client connection.
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		resp.Body.Close()
		upstream.Close()
		return
	}
	resp.Body.Close()

	// Write 101 response to client.
	respRaw, _ := httputil.DumpResponse(resp, false)
	clientBuf.Write(respRaw) //nolint:errcheck
	clientBuf.Flush()        //nolint:errcheck

	// Capture the upgrade request in HTTP store.
	start := timeNow()
	captured := &CapturedRequest{
		ID:           id,
		Timestamp:    start,
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         r.Host,
		StatusCode:   resp.StatusCode,
		Duration:     0,
		ResponseSize: len(respRaw),
		ReqRaw:       raw,
		RespRaw:      respRaw,
	}
	h.store.Add(captured)
	h.emit(eventRequestCaptured(captured))

	connID := GenerateID()
	h.wsRelay(connID, r.Host, r.URL.String(), clientConn, upstream, clientBuf.Reader)
}

// handleWSUpgradeMITM handles WebSocket upgrades detected within the MITM TLS loop.
func (h *Handler) handleWSUpgradeMITM(tlsConn net.Conn, req *http.Request, hostname string) {
	// Dial upstream with TLS.
	host := hostname + ":443"

	var rawUpstream net.Conn
	var err error
	if dialCtx := h.transport.SOCKSDialContext(); dialCtx != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rawUpstream, err = dialCtx(ctx, "tcp", host)
	} else {
		rawUpstream, err = net.DialTimeout("tcp", host, 10*time.Second)
	}
	if err != nil {
		writeSimpleResponse(tlsConn, http.StatusBadGateway, "upstream dial error: "+err.Error())
		return
	}

	upstream := tls.Client(rawUpstream, newUpstreamTLSConfig(hostname, nil))
	if err := upstream.Handshake(); err != nil {
		rawUpstream.Close()
		writeSimpleResponse(tlsConn, http.StatusBadGateway, "upstream TLS error: "+err.Error())
		return
	}

	// Write the upgrade request to upstream.
	raw, _ := httputil.DumpRequest(req, true)
	if _, err := upstream.Write(raw); err != nil {
		upstream.Close()
		writeSimpleResponse(tlsConn, http.StatusBadGateway, "upstream write error")
		return
	}

	// Read upstream response.
	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		upstream.Close()
		writeSimpleResponse(tlsConn, http.StatusBadGateway, "upstream response error")
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Write(tlsConn) //nolint:errcheck
		resp.Body.Close()
		upstream.Close()
		return
	}
	resp.Body.Close()

	// Write 101 response to client.
	respRaw, _ := httputil.DumpResponse(resp, false)
	tlsConn.Write(respRaw) //nolint:errcheck

	// Capture the upgrade request in HTTP store.
	id := GenerateID()
	start := timeNow()
	captured := &CapturedRequest{
		ID:           id,
		Timestamp:    start,
		Method:       req.Method,
		URL:          req.URL.String(),
		Host:         hostname,
		StatusCode:   resp.StatusCode,
		Duration:     0,
		ResponseSize: len(respRaw),
		ReqRaw:       raw,
		RespRaw:      respRaw,
	}
	h.store.Add(captured)
	h.emit(eventRequestCaptured(captured))

	connID := GenerateID()
	h.wsRelay(connID, hostname, req.URL.String(), tlsConn, upstream, nil)
}

// wsRelay relays WebSocket frames bidirectionally between client and upstream.
// clientReader is an optional pre-existing bufio.Reader wrapping clientConn (from hijack).
func (h *Handler) wsRelay(connID, host, urlStr string, clientConn, upstreamConn net.Conn, clientReader *bufio.Reader) {
	defer clientConn.Close()
	defer upstreamConn.Close()

	var clientR io.Reader = clientConn
	if clientReader != nil {
		clientR = clientReader
	}
	upstreamR := bufio.NewReader(upstreamConn)

	var wg sync.WaitGroup
	wg.Add(2)

	// client → server
	go func() {
		defer wg.Done()
		h.relayFrames(connID, host, urlStr, clientR, upstreamConn, "client_to_server", true)
	}()

	// server → client
	go func() {
		defer wg.Done()
		h.relayFrames(connID, host, urlStr, upstreamR, clientConn, "server_to_client", false)
	}()

	wg.Wait()
}

// relayFrames reads frames from src and writes them to dst, capturing messages.
// masked indicates whether outgoing frames should be masked (client→server = true).
func (h *Handler) relayFrames(connID, host, urlStr string, src io.Reader, dst net.Conn, direction string, masked bool) {
	var msgBuf []byte
	var msgOpcode byte

	for {
		frame, err := ReadFrame(src)
		if err != nil {
			// Send close frame on read error.
			closeFrame := &WSFrame{FIN: true, Opcode: wsOpClose}
			WriteFrame(dst, closeFrame, masked) //nolint:errcheck
			return
		}

		// Control frames: forward immediately without match/replace.
		if frame.IsControl() {
			WriteFrame(dst, frame, masked) //nolint:errcheck
			if frame.Opcode == wsOpClose {
				return
			}
			continue
		}

		// Data frames: accumulate continuation frames until FIN.
		if frame.Opcode != wsOpContinuation {
			msgOpcode = frame.Opcode
			msgBuf = append(msgBuf[:0], frame.Payload...)
		} else {
			msgBuf = append(msgBuf, frame.Payload...)
		}

		if !frame.FIN {
			continue
		}

		// Complete message — apply match/replace.
		if h.replace != nil {
			msgBuf = h.replace.Apply("ws_message", msgBuf)
		}

		// Capture the message.
		isText := msgOpcode == wsOpText
		msg := &CapturedWSMessage{
			ID:            GenerateID(),
			ConnectionID:  connID,
			Timestamp:     timeNow(),
			Direction:     direction,
			Opcode:        msgOpcode,
			PayloadLength: len(msgBuf),
			Host:          host,
			URL:           urlStr,
			IsText:        isText,
		}
		if isText {
			msg.Payload = string(msgBuf)
		} else {
			msg.Payload = fmt.Sprintf("%x", msgBuf)
		}

		if h.wsStore != nil {
			h.wsStore.Add(msg)
		}
		h.emit(eventWSMessage(msg))

		// Forward as a single frame.
		outFrame := &WSFrame{
			FIN:     true,
			Opcode:  msgOpcode,
			Payload: msgBuf,
		}
		if err := WriteFrame(dst, outFrame, masked); err != nil {
			return
		}

		msgBuf = msgBuf[:0]
	}
}
