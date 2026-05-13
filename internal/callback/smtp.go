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
	"net/mail"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/event"
)

const (
	smtpMaxLine     = 1000          // RFC 5321 §4.5.3.1.6
	smtpMaxData     = 1 << 20       // 1 MiB cap on DATA payload
	smtpMaxRcpts    = 5             // bound per-session memory
	smtpIdleTimeout = 5 * time.Minute
)

// SMTPServer listens for SMTP connections and records inbound mail as
// callback interactions. It is a capture-only server — no relay, no AUTH.
type SMTPServer struct {
	store         *Store
	broadcast     chan<- any
	bindAddr      string
	plainPort     int
	tlsPort       int
	tlsCfg        *tls.Config
	plainListener net.Listener
	tlsListener   net.Listener
}

// NewSMTPServer creates an SMTP capture server. plainPort=0 disables the
// plain listener; tlsPort=0 disables the implicit-TLS (SMTPS) listener.
// tlsCfg=nil disables STARTTLS on the plain listener.
func NewSMTPServer(store *Store, broadcast chan<- any, bindAddr string,
	plainPort, tlsPort int, tlsCfg *tls.Config) *SMTPServer {
	return &SMTPServer{
		store:     store,
		broadcast: broadcast,
		bindAddr:  bindAddr,
		plainPort: plainPort,
		tlsPort:   tlsPort,
		tlsCfg:    tlsCfg,
	}
}

// Start opens the configured listeners and accepts connections until ctx
// is cancelled.
func (s *SMTPServer) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	if s.plainPort > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindAddr, s.plainPort))
		if err != nil {
			return fmt.Errorf("smtp plain listen: %w", err)
		}
		s.plainListener = ln
		go s.acceptLoop(ln, false, errCh)
	}

	if s.tlsPort > 0 {
		if s.tlsCfg == nil {
			return fmt.Errorf("smtps requires a TLS config")
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindAddr, s.tlsPort))
		if err != nil {
			return fmt.Errorf("smtps listen: %w", err)
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

func (s *SMTPServer) acceptLoop(ln net.Listener, implicitTLS bool, errCh chan<- error) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		go s.handleConnection(conn, implicitTLS)
	}
}

// smtpSession holds per-connection state. STARTTLS resets all fields except
// the underlying conn (which gets wrapped).
type smtpSession struct {
	from       string
	rcpts      []string
	transcript bytes.Buffer
	isTLS      bool
}

func (s *SMTPServer) handleConnection(conn net.Conn, implicitTLS bool) {
	defer conn.Close() //nolint:errcheck

	if implicitTLS {
		tlsConn := tls.Server(conn, s.tlsCfg)
		if err := tlsConn.SetDeadline(time.Now().Add(smtpIdleTimeout)); err == nil {
			if err := tlsConn.Handshake(); err != nil {
				return
			}
		}
		conn = tlsConn
	}

	sess := &smtpSession{isTLS: implicitTLS}
	rw := bufio.NewReadWriter(bufio.NewReaderSize(conn, smtpMaxLine+2), bufio.NewWriter(conn))

	s.writeLine(rw, sess, "220 joro ESMTP ready")

	for {
		conn.SetReadDeadline(time.Now().Add(smtpIdleTimeout)) //nolint:errcheck
		line, err := s.readLine(rw)
		if err != nil {
			return
		}
		sess.transcript.WriteString("C: ")
		sess.transcript.WriteString(line)
		sess.transcript.WriteString("\r\n")

		verb, rest := splitVerb(line)
		switch strings.ToUpper(verb) {
		case "HELO":
			sess.from, sess.rcpts = "", nil
			s.writeLine(rw, sess, "250 joro")
		case "EHLO":
			sess.from, sess.rcpts = "", nil
			lines := []string{"250-joro", fmt.Sprintf("250-SIZE %d", smtpMaxData)}
			if s.tlsCfg != nil && !sess.isTLS {
				lines = append(lines, "250-STARTTLS")
			}
			lines = append(lines, "250 HELP")
			s.writeLines(rw, sess, lines)
		case "STARTTLS":
			if s.tlsCfg == nil || sess.isTLS {
				s.writeLine(rw, sess, "502 STARTTLS not available")
				continue
			}
			s.writeLine(rw, sess, "220 Ready to start TLS")
			rw.Flush() //nolint:errcheck
			tlsConn := tls.Server(conn, s.tlsCfg)
			if err := tlsConn.SetDeadline(time.Now().Add(smtpIdleTimeout)); err != nil {
				return
			}
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			rw = bufio.NewReadWriter(bufio.NewReaderSize(conn, smtpMaxLine+2), bufio.NewWriter(conn))
			sess = &smtpSession{isTLS: true}
		case "MAIL":
			sess.from = parseAddrParam(rest, "FROM")
			sess.rcpts = nil
			s.writeLine(rw, sess, "250 OK")
		case "RCPT":
			addr := parseAddrParam(rest, "TO")
			if addr != "" && len(sess.rcpts) < smtpMaxRcpts {
				sess.rcpts = append(sess.rcpts, addr)
			}
			s.writeLine(rw, sess, "250 OK")
		case "DATA":
			if len(sess.rcpts) == 0 {
				s.writeLine(rw, sess, "503 Need RCPT before DATA")
				continue
			}
			s.writeLine(rw, sess, "354 End data with <CR><LF>.<CR><LF>")
			data, err := s.readData(rw, sess)
			if err != nil {
				return
			}
			s.recordMessage(conn, sess, data)
			s.writeLine(rw, sess, "250 OK queued")
			sess.from, sess.rcpts = "", nil
		case "RSET":
			sess.from, sess.rcpts = "", nil
			s.writeLine(rw, sess, "250 OK")
		case "NOOP":
			s.writeLine(rw, sess, "250 OK")
		case "QUIT":
			s.writeLine(rw, sess, "221 Bye")
			return
		case "VRFY", "EXPN":
			s.writeLine(rw, sess, "252 Cannot VRFY user, but will accept message")
		default:
			s.writeLine(rw, sess, "502 Command not implemented")
		}
	}
}

func (s *SMTPServer) readLine(rw *bufio.ReadWriter) (string, error) {
	line, err := rw.Reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > smtpMaxLine {
		return "", io.ErrShortBuffer
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (s *SMTPServer) readData(rw *bufio.ReadWriter, sess *smtpSession) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := rw.Reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		sess.transcript.WriteString("C: ")
		sess.transcript.WriteString(trimmed)
		sess.transcript.WriteString("\r\n")
		if trimmed == "." {
			break
		}
		trimmed = strings.TrimPrefix(trimmed, ".")
		if buf.Len()+len(trimmed)+2 > smtpMaxData {
			// Drain remaining DATA but cap stored payload.
			continue
		}
		buf.WriteString(trimmed)
		buf.WriteString("\r\n")
	}
	return buf.Bytes(), nil
}

func (s *SMTPServer) writeLine(rw *bufio.ReadWriter, sess *smtpSession, line string) {
	sess.transcript.WriteString("S: ")
	sess.transcript.WriteString(line)
	sess.transcript.WriteString("\r\n")
	rw.WriteString(line + "\r\n") //nolint:errcheck
	rw.Flush()                    //nolint:errcheck
}

func (s *SMTPServer) writeLines(rw *bufio.ReadWriter, sess *smtpSession, lines []string) {
	for _, l := range lines {
		sess.transcript.WriteString("S: ")
		sess.transcript.WriteString(l)
		sess.transcript.WriteString("\r\n")
		rw.WriteString(l + "\r\n") //nolint:errcheck
	}
	rw.Flush() //nolint:errcheck
}

func (s *SMTPServer) recordMessage(conn net.Conn, sess *smtpSession, data []byte) {
	cfg, _ := s.store.GetConfig()
	domain := cfg.Domain

	var token *Token
	var matchedRcpt string
	for _, rcpt := range sess.rcpts {
		if tok, err := CorrelateSMTP(s.store, rcpt, domain); err == nil {
			token = tok
			matchedRcpt = rcpt
			break
		}
	}
	if token == nil {
		return
	}

	var hdrFrom, hdrTo, hdrSubject, body string
	if msg, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
		hdrFrom = msg.Header.Get("From")
		hdrTo = msg.Header.Get("To")
		hdrSubject = msg.Header.Get("Subject")
		if bodyBytes, err := io.ReadAll(msg.Body); err == nil {
			body = string(bodyBytes)
		}
	}
	if body == "" {
		body = string(data)
	}

	headers, _ := json.Marshal(map[string]string{
		"from":          hdrFrom,
		"to":            hdrTo,
		"subject":       hdrSubject,
		"envelope_from": sess.from,
		"envelope_to":   strings.Join(sess.rcpts, ", "),
		"matched_rcpt":  matchedRcpt,
		"tls":           fmt.Sprintf("%t", sess.isTLS),
	})

	sourceIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	id := make([]byte, 16)
	rand.Read(id) //nolint:errcheck

	interaction := &Interaction{
		ID:         hex.EncodeToString(id),
		TokenID:    token.ID,
		Token:      token.Token,
		Type:       "smtp",
		SourceIP:   sourceIP,
		Timestamp:  time.Now().UTC(),
		Headers:    string(headers),
		Body:       base64.StdEncoding.EncodeToString([]byte(body)),
		RawRequest: base64.StdEncoding.EncodeToString(sess.transcript.Bytes()),
	}
	if err := s.store.RecordInteraction(interaction); err != nil {
		log.Printf("callback smtp: record interaction: %v", err)
		return
	}
	s.broadcast <- event.WSEvent{Type: "callback.interaction", Data: interaction}
}

// splitVerb returns the first whitespace-delimited token and the remainder.
func splitVerb(line string) (verb, rest string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return line[:i], strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

// parseAddrParam extracts the address from "MAIL FROM:<addr>" / "RCPT TO:<addr>"
// arguments. Param is "FROM" or "TO" (case-insensitive). Returns the address
// without surrounding angle brackets; ignores trailing SIZE= and other params.
func parseAddrParam(rest, param string) string {
	rest = strings.TrimSpace(rest)
	upper := strings.ToUpper(rest)
	prefix := param + ":"
	if !strings.HasPrefix(upper, prefix) {
		return ""
	}
	rest = strings.TrimSpace(rest[len(prefix):])
	end := len(rest)
	if i := strings.Index(rest, " "); i >= 0 {
		end = i
	}
	addr := strings.TrimSpace(rest[:end])
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	return addr
}
