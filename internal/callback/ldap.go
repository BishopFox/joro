package callback

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/BishopFox/joro/internal/event"
)

const (
	ldapMaxMessage  = 1 << 16 // 64 KiB cap on a single LDAPMessage
	ldapIdleTimeout = 2 * time.Minute
	ldapMaxMessages = 20 // per-connection message cap
	ldapMaxIDLen    = 8  // cap on the messageID INTEGER we echo back
)

// LDAP BER tags we care about.
const (
	berSequence       = 0x30 // universal SEQUENCE (constructed)
	berInteger        = 0x02 // universal INTEGER
	berOctetString    = 0x04 // universal OCTET STRING
	ldapBindRequest   = 0x60 // [APPLICATION 0] constructed
	ldapUnbindRequest = 0x42 // [APPLICATION 2] primitive
	ldapSearchRequest = 0x63 // [APPLICATION 3] constructed
	ldapBindResponse  = 0x61 // [APPLICATION 1] constructed
	ldapSearchDone    = 0x65 // [APPLICATION 5] constructed
)

// LDAPServer listens for LDAP connections and records them as callback
// interactions. It is a capture-only server that parses just enough BER to
// extract the bind DN / search baseObject (where JNDI/Log4Shell payloads place
// data) and replies with canned success responses so the client completes.
type LDAPServer struct {
	store         *Store
	broadcast     chan<- any
	bindAddr      string
	plainPort     int
	tlsPort       int
	tlsCfg        *tls.Config
	plainListener net.Listener
	tlsListener   net.Listener
}

// NewLDAPServer creates an LDAP capture server. plainPort=0 disables the plain
// listener; tlsPort=0 disables the implicit-TLS (LDAPS) listener. tlsCfg must
// be non-nil if tlsPort>0.
func NewLDAPServer(store *Store, broadcast chan<- any, bindAddr string,
	plainPort, tlsPort int, tlsCfg *tls.Config) *LDAPServer {
	return &LDAPServer{
		store:     store,
		broadcast: broadcast,
		bindAddr:  bindAddr,
		plainPort: plainPort,
		tlsPort:   tlsPort,
		tlsCfg:    tlsCfg,
	}
}

// Start opens the configured listeners and accepts connections until ctx is
// cancelled.
func (s *LDAPServer) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	if s.plainPort > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindAddr, s.plainPort))
		if err != nil {
			return fmt.Errorf("ldap plain listen: %w", err)
		}
		s.plainListener = ln
		go s.acceptLoop(ln, false, errCh)
	}

	if s.tlsPort > 0 {
		if s.tlsCfg == nil {
			return fmt.Errorf("ldaps requires a TLS config")
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindAddr, s.tlsPort))
		if err != nil {
			return fmt.Errorf("ldaps listen: %w", err)
		}
		s.tlsListener = ln
		go s.acceptLoop(ln, true, errCh)
	}

	go func() {
		<-ctx.Done()
		if s.plainListener != nil {
			s.plainListener.Close() //nolint:errcheck
		}
		if s.tlsListener != nil {
			s.tlsListener.Close() //nolint:errcheck
		}
	}()

	return <-errCh
}

func (s *LDAPServer) acceptLoop(ln net.Listener, implicitTLS bool, errCh chan<- error) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		go s.handleConnection(conn, implicitTLS)
	}
}

// ldapSession holds per-connection capture state.
type ldapSession struct {
	bindDN     string
	searchBase string
	raw        bytes.Buffer // concatenated raw bytes of every message
	messages   int
	isTLS      bool
	gotOp      bool // saw at least one bind/search we can correlate on
}

func (s *LDAPServer) handleConnection(conn net.Conn, implicitTLS bool) {
	// Containment: the hand-rolled BER parser must never crash the process on
	// malformed input — drop the connection instead.
	defer func() { _ = recover() }()
	defer conn.Close() //nolint:errcheck

	if implicitTLS {
		tlsConn := tls.Server(conn, s.tlsCfg)
		if err := tlsConn.SetDeadline(time.Now().Add(ldapIdleTimeout)); err != nil {
			return
		}
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	}

	sess := &ldapSession{isTLS: implicitTLS}
	defer s.record(conn, sess)

	r := bufio.NewReader(conn)
	for sess.messages < ldapMaxMessages {
		conn.SetReadDeadline(time.Now().Add(ldapIdleTimeout)) //nolint:errcheck

		msg, err := readRawMessage(r)
		if err != nil {
			return
		}
		sess.messages++
		sess.raw.Write(msg)

		stop := s.handleMessage(conn, sess, msg)
		if stop {
			return
		}
	}
}

// handleMessage parses one LDAPMessage, records extracted fields, writes a
// canned response, and returns true if the connection should close.
func (s *LDAPServer) handleMessage(conn net.Conn, sess *ldapSession, msg []byte) bool {
	tag, body, _, err := readTLV(bufio.NewReader(bytes.NewReader(msg)), ldapMaxMessage)
	if err != nil || tag != berSequence {
		return true
	}
	seq := bufio.NewReader(bytes.NewReader(body))

	// messageID INTEGER — keep the raw TLV value to echo back verbatim.
	idTag, idBytes, _, err := readTLV(seq, ldapMaxIDLen)
	if err != nil || idTag != berInteger {
		return true
	}

	// protocolOp.
	opTag, opBody, _, err := readTLV(seq, ldapMaxMessage)
	if err != nil {
		return true
	}

	switch opTag {
	case ldapBindRequest:
		op := bufio.NewReader(bytes.NewReader(opBody))
		// version INTEGER (ignored).
		if vt, _, _, e := readTLV(op, ldapMaxMessage); e != nil || vt != berInteger {
			return true
		}
		// name LDAPDN (OCTET STRING) = bind DN.
		if nt, name, _, e := readTLV(op, ldapMaxMessage); e == nil && nt == berOctetString {
			sess.bindDN = string(name)
			sess.gotOp = true
		}
		s.writeResponse(conn, idBytes, ldapBindResponse)
		return false

	case ldapSearchRequest:
		op := bufio.NewReader(bytes.NewReader(opBody))
		// baseObject LDAPDN (OCTET STRING).
		if bt, base, _, e := readTLV(op, ldapMaxMessage); e == nil && bt == berOctetString {
			sess.searchBase = string(base)
			sess.gotOp = true
		}
		s.writeResponse(conn, idBytes, ldapSearchDone)
		return false

	case ldapUnbindRequest:
		return true

	default:
		// AbandonRequest, ExtendedRequest, etc. — nothing to correlate; keep
		// reading in case a bind/search follows.
		return false
	}
}

// writeResponse builds and sends a minimal success LDAPMessage echoing the
// given messageID INTEGER value. opTag is ldapBindResponse or ldapSearchDone.
func (s *LDAPServer) writeResponse(conn net.Conn, idBytes []byte, opTag byte) {
	// LDAPResult: resultCode=success(0), matchedDN="", diagnosticMessage="".
	resultBody := []byte{0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	op := ber(opTag, resultBody)
	inner := append(ber(berInteger, idBytes), op...)
	msg := ber(berSequence, inner)
	conn.Write(msg) //nolint:errcheck
}

// record correlates and stores the session. Runs once via defer; no-ops if no
// bind/search was seen or no token correlates.
func (s *LDAPServer) record(conn net.Conn, sess *ldapSession) {
	if !sess.gotOp {
		return
	}

	token, err := CorrelateAny(s.store,
		sess.searchBase, sess.bindDN,
		hex.EncodeToString(sess.raw.Bytes()),
	)
	if err != nil {
		return
	}

	headers, _ := json.Marshal(map[string]string{
		"bind_dn":     sess.bindDN,
		"search_base": sess.searchBase,
		"messages":    fmt.Sprintf("%d", sess.messages),
		"tls":         fmt.Sprintf("%t", sess.isTLS),
	})

	queryName := sess.searchBase
	if queryName == "" {
		queryName = sess.bindDN
	}

	sourceIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	id := make([]byte, 16)
	rand.Read(id) //nolint:errcheck

	interaction := &Interaction{
		ID:         hex.EncodeToString(id),
		TokenID:    token.ID,
		Token:      token.Token,
		Type:       "ldap",
		SourceIP:   sourceIP,
		Timestamp:  time.Now().UTC(),
		QueryName:  queryName,
		Headers:    string(headers),
		RawRequest: base64.StdEncoding.EncodeToString(sess.raw.Bytes()),
	}
	if err := s.store.RecordInteraction(interaction); err != nil {
		log.Printf("callback ldap: record interaction: %v", err)
		return
	}
	s.broadcast <- event.WSEvent{Type: "callback.interaction", Data: interaction}
}

// readRawMessage reads one complete top-level BER TLV (an LDAPMessage) from r
// and returns its full bytes (tag + length + value), so the captured raw
// transcript is byte-accurate. Definite-length only; enforces ldapMaxMessage.
func readRawMessage(r *bufio.Reader) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag&0x1f == 0x1f {
		return nil, fmt.Errorf("ldap: high-tag-number form unsupported")
	}

	hdr := []byte{tag}
	lb, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	hdr = append(hdr, lb)

	var length int
	if lb&0x80 == 0 {
		length = int(lb)
	} else {
		n := int(lb & 0x7f)
		if n == 0 || n > 4 {
			return nil, fmt.Errorf("ldap: bad long-form length")
		}
		for range n {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			hdr = append(hdr, b)
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > ldapMaxMessage {
		return nil, fmt.Errorf("ldap: message too large")
	}

	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, err
	}
	return append(hdr, value...), nil
}

// readTLV reads one definite-length BER tag+length+value from r, enforcing
// maxLen on the value size. Returns the tag byte, the value bytes, and the
// total number of bytes consumed (header + value).
func readTLV(r *bufio.Reader, maxLen int) (tag byte, value []byte, consumed int, err error) {
	tag, err = r.ReadByte()
	if err != nil {
		return 0, nil, 0, err
	}
	if tag&0x1f == 0x1f {
		return 0, nil, 0, fmt.Errorf("ldap: high-tag-number form unsupported")
	}
	consumed = 1

	lb, err := r.ReadByte()
	if err != nil {
		return 0, nil, 0, err
	}
	consumed++

	var length int
	if lb&0x80 == 0 {
		length = int(lb)
	} else {
		n := int(lb & 0x7f)
		if n == 0 || n > 4 {
			return 0, nil, 0, fmt.Errorf("ldap: bad long-form length")
		}
		for range n {
			b, e := r.ReadByte()
			if e != nil {
				return 0, nil, 0, e
			}
			consumed++
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > maxLen {
		return 0, nil, 0, fmt.Errorf("ldap: value too large")
	}

	value = make([]byte, length)
	if _, err = io.ReadFull(r, value); err != nil {
		return 0, nil, 0, err
	}
	consumed += length
	return tag, value, consumed, nil
}

// ber builds a definite short-form BER TLV. content must be < 128 bytes (true
// for all canned LDAP responses we emit).
func ber(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+2)
	out = append(out, tag, byte(len(content)))
	out = append(out, content...)
	return out
}
