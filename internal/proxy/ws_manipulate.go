package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ManipulateWSState is the lifecycle state of a ManipulateWSSession.
type ManipulateWSState int32

const (
	ManipulateWSConnecting ManipulateWSState = iota
	ManipulateWSOpen
	ManipulateWSClosed
)

// ManipulateWSFrameCallback is invoked once per complete incoming message.
// Sent frames are reported via the same callback so the UI can render a
// unified transcript.
type ManipulateWSFrameCallback func(direction string, opcode byte, payload []byte, ts time.Time)

// ManipulateWSCloseCallback is invoked exactly once when the session closes,
// either due to remote close, read error, or a call to Close.
type ManipulateWSCloseCallback func(reason string)

// ManipulateWSSession is a client-initiated WebSocket connection whose raw
// upgrade handshake was authored by the user. Frames are sent on demand via
// Send; incoming frames are reassembled across continuations and delivered
// via the session's onFrame callback.
type ManipulateWSSession struct {
	ID        string
	URL       string
	createdAt time.Time

	conn  net.Conn
	state atomic.Int32

	writeMu sync.Mutex

	onFrame ManipulateWSFrameCallback
	onClose ManipulateWSCloseCallback

	closeOnce sync.Once
	closeErr  error
}

// State returns the current lifecycle state.
func (s *ManipulateWSSession) State() ManipulateWSState {
	return ManipulateWSState(s.state.Load())
}

// ManipulateWSManager tracks active user-driven WS sessions.
type ManipulateWSManager struct {
	mu        sync.RWMutex
	sessions  map[string]*ManipulateWSSession
	transport *TransportConfig
}

// NewManipulateWSManager returns a manager. transport may be nil, in which
// case plain net.Dial / tls.Dial are used.
func NewManipulateWSManager(transport *TransportConfig) *ManipulateWSManager {
	return &ManipulateWSManager{
		sessions:  make(map[string]*ManipulateWSSession),
		transport: transport,
	}
}

// Get returns a session by ID or nil.
func (m *ManipulateWSManager) Get(id string) *ManipulateWSSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// Dial opens a WebSocket connection to host using the exact rawUpgrade bytes
// supplied by the user (with a best-effort Sec-WebSocket-Key fill-in if the
// header is missing). It returns the session (open and reading in the
// background), the raw upgrade response bytes, and an error.
//
// On non-101 response, the error is non-nil but rawResp is still populated so
// the caller can show the server's rejection in the UI.
func (m *ManipulateWSManager) Dial(
	rawUpgrade []byte,
	scheme, host string,
	onFrame ManipulateWSFrameCallback,
	onClose ManipulateWSCloseCallback,
) (*ManipulateWSSession, []byte, error) {
	scheme = strings.ToLower(scheme)
	if scheme != "ws" && scheme != "wss" {
		return nil, nil, fmt.Errorf("invalid scheme %q (want ws or wss)", scheme)
	}
	if host == "" {
		return nil, nil, errors.New("host is required")
	}
	if !hasPort(host) {
		if scheme == "wss" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}

	rawUpgrade = ensureWebSocketKey(rawUpgrade)

	conn, err := m.dialConn(scheme, host)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}

	if _, err := conn.Write(rawUpgrade); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read upgrade response: %w", err)
	}

	rawResp, _ := httputil.DumpResponse(resp, true)
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, rawResp, fmt.Errorf("upgrade failed: %s", resp.Status)
	}

	sess := &ManipulateWSSession{
		ID:        GenerateID(),
		URL:       scheme + "://" + host + requestTarget(rawUpgrade),
		createdAt: time.Now(),
		conn:      conn,
		onFrame:   onFrame,
		onClose:   onClose,
	}
	sess.state.Store(int32(ManipulateWSOpen))

	m.mu.Lock()
	m.sessions[sess.ID] = sess
	m.mu.Unlock()

	go m.readLoop(sess, br)

	return sess, rawResp, nil
}

// Send writes a single FIN data/control frame with the given opcode and
// payload. The client side always masks outgoing frames. The sent frame is
// also dispatched to the session's onFrame callback so the UI transcript is
// updated consistently.
func (m *ManipulateWSManager) Send(id string, opcode byte, payload []byte) error {
	sess := m.Get(id)
	if sess == nil {
		return fmt.Errorf("unknown session %s", id)
	}
	if sess.State() != ManipulateWSOpen {
		return errors.New("session not open")
	}
	if len(payload) > wsMaxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes", len(payload))
	}

	frame := &WSFrame{FIN: true, Opcode: opcode & 0x0F, Payload: payload}

	sess.writeMu.Lock()
	err := WriteFrame(sess.conn, frame, true)
	sess.writeMu.Unlock()
	if err != nil {
		return err
	}

	if sess.onFrame != nil {
		sess.onFrame("sent", frame.Opcode, append([]byte(nil), payload...), time.Now())
	}
	return nil
}

// Close sends a close frame (if still open) and tears down the session.
// Repeated calls are safe.
func (m *ManipulateWSManager) Close(id, reason string) error {
	sess := m.Get(id)
	if sess == nil {
		return nil
	}
	sess.closeOnce.Do(func() {
		if sess.state.Swap(int32(ManipulateWSClosed)) == int32(ManipulateWSOpen) {
			sess.writeMu.Lock()
			WriteFrame(sess.conn, &WSFrame{FIN: true, Opcode: wsOpClose}, true) //nolint:errcheck
			sess.writeMu.Unlock()
		}
		sess.conn.Close()

		m.mu.Lock()
		delete(m.sessions, sess.ID)
		m.mu.Unlock()

		if sess.onClose != nil {
			sess.onClose(reason)
		}
	})
	return nil
}

// readLoop reassembles incoming frames and dispatches complete messages
// through onFrame. Control frames are delivered immediately. On any read
// error or a close frame, the session is torn down.
func (m *ManipulateWSManager) readLoop(sess *ManipulateWSSession, br *bufio.Reader) {
	var msgBuf []byte
	var msgOpcode byte

	for {
		frame, err := ReadFrame(br)
		if err != nil {
			reason := err.Error()
			if errors.Is(err, io.EOF) {
				reason = "eof"
			}
			m.Close(sess.ID, reason)
			return
		}

		if frame.IsControl() {
			if sess.onFrame != nil {
				sess.onFrame("received", frame.Opcode, append([]byte(nil), frame.Payload...), time.Now())
			}
			if frame.Opcode == wsOpClose {
				m.Close(sess.ID, "peer closed")
				return
			}
			// Respond to ping with a pong.
			if frame.Opcode == wsOpPing {
				pong := &WSFrame{FIN: true, Opcode: wsOpPong, Payload: frame.Payload}
				sess.writeMu.Lock()
				WriteFrame(sess.conn, pong, true) //nolint:errcheck
				sess.writeMu.Unlock()
			}
			continue
		}

		if frame.Opcode != wsOpContinuation {
			msgOpcode = frame.Opcode
			msgBuf = append(msgBuf[:0], frame.Payload...)
		} else {
			msgBuf = append(msgBuf, frame.Payload...)
		}

		if !frame.FIN {
			continue
		}

		if sess.onFrame != nil {
			sess.onFrame("received", msgOpcode, append([]byte(nil), msgBuf...), time.Now())
		}
		msgBuf = msgBuf[:0]
	}
}

// dialConn opens a TCP or TLS connection to host, honoring the SOCKS
// configuration on the transport if one is present.
func (m *ManipulateWSManager) dialConn(scheme, host string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var raw net.Conn
	var err error
	if m.transport != nil {
		if dialCtx := m.transport.SOCKSDialContext(); dialCtx != nil {
			raw, err = dialCtx(ctx, "tcp", host)
		}
	}
	if raw == nil && err == nil {
		raw, err = net.DialTimeout("tcp", host, 10*time.Second)
	}
	if err != nil {
		return nil, err
	}

	if scheme != "wss" {
		return raw, nil
	}

	serverName, _, _ := net.SplitHostPort(host)
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec
	})
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tlsConn, nil
}

// ensureWebSocketKey inserts a random Sec-WebSocket-Key header if one is not
// already present in the raw upgrade bytes.
func ensureWebSocketKey(raw []byte) []byte {
	headers, rest, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return raw
	}
	if bytes.Contains(bytes.ToLower(headers), []byte("sec-websocket-key:")) {
		return raw
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return raw
	}
	hdr := "\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(keyBytes)
	out := make([]byte, 0, len(raw)+len(hdr)+4)
	out = append(out, headers...)
	out = append(out, hdr...)
	out = append(out, "\r\n\r\n"...)
	out = append(out, rest...)
	return out
}

// requestTarget extracts the path+query from the first line of a raw HTTP
// request, returning "/" on failure.
func requestTarget(raw []byte) string {
	firstLine, _, _ := bytes.Cut(raw, []byte("\r\n"))
	parts := bytes.Fields(firstLine)
	if len(parts) < 2 {
		return "/"
	}
	return string(parts[1])
}

// hasPort reports whether host already includes a ":port" suffix.
func hasPort(host string) bool {
	_, _, err := net.SplitHostPort(host)
	return err == nil
}

// OpcodeName maps a WS opcode to its wire name for JSON payloads.
func OpcodeName(op byte) string {
	switch op & 0x0F {
	case wsOpContinuation:
		return "continuation"
	case wsOpText:
		return "text"
	case wsOpBinary:
		return "binary"
	case wsOpClose:
		return "close"
	case wsOpPing:
		return "ping"
	case wsOpPong:
		return "pong"
	}
	return fmt.Sprintf("opcode-%x", op&0x0F)
}

// OpcodeFromName is the inverse of OpcodeName. Returns (0, false) if unknown.
func OpcodeFromName(name string) (byte, bool) {
	switch strings.ToLower(name) {
	case "text":
		return wsOpText, true
	case "binary":
		return wsOpBinary, true
	case "ping":
		return wsOpPing, true
	case "pong":
		return wsOpPong, true
	case "close":
		return wsOpClose, true
	case "continuation":
		return wsOpContinuation, true
	}
	return 0, false
}
