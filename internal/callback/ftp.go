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
	"log"
	"net"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/event"
)

const (
	ftpMaxLine     = 4096
	ftpIdleTimeout = 2 * time.Minute
	ftpMaxCommands = 100
	ftpMaxPaths    = 20 // bound per-session memory
)

// FTPServer listens for FTP connections and records them as callback
// interactions. It is a capture-only server — it never opens a data channel,
// completes a transfer, or authenticates a user. The correlation token is
// expected in the USER argument or a path argument (e.g. CWD/RETR), which are
// captured before any data transfer would occur.
type FTPServer struct {
	store         *Store
	broadcast     chan<- any
	bindAddr      string
	plainPort     int
	tlsPort       int
	tlsCfg        *tls.Config
	plainListener net.Listener
	tlsListener   net.Listener
}

// NewFTPServer creates an FTP capture server. plainPort=0 disables the plain
// listener; tlsPort=0 disables the implicit-TLS (FTPS) listener. tlsCfg must be
// non-nil if tlsPort>0.
func NewFTPServer(store *Store, broadcast chan<- any, bindAddr string,
	plainPort, tlsPort int, tlsCfg *tls.Config) *FTPServer {
	return &FTPServer{
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
func (s *FTPServer) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	if s.plainPort > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindAddr, s.plainPort))
		if err != nil {
			return fmt.Errorf("ftp plain listen: %w", err)
		}
		s.plainListener = ln
		go s.acceptLoop(ln, false, errCh)
	}

	if s.tlsPort > 0 {
		if s.tlsCfg == nil {
			return fmt.Errorf("ftps requires a TLS config")
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindAddr, s.tlsPort))
		if err != nil {
			return fmt.Errorf("ftps listen: %w", err)
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

func (s *FTPServer) acceptLoop(ln net.Listener, implicitTLS bool, errCh chan<- error) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		go s.handleConnection(conn, implicitTLS)
	}
}

// ftpSession holds per-connection state.
type ftpSession struct {
	user       string
	pass       string
	pathArgs   []string
	transcript bytes.Buffer
	isTLS      bool
	sawUser    bool
}

func (s *FTPServer) handleConnection(conn net.Conn, implicitTLS bool) {
	// Containment: this parses untrusted network input, so a panic must drop
	// the single connection rather than crash the process.
	defer func() { _ = recover() }()
	defer conn.Close() //nolint:errcheck

	if implicitTLS {
		tlsConn := tls.Server(conn, s.tlsCfg)
		if err := tlsConn.SetDeadline(time.Now().Add(ftpIdleTimeout)); err != nil {
			return
		}
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	}

	sess := &ftpSession{isTLS: implicitTLS}
	// Record on exit (defer-guarded once) so we capture even clients that
	// disconnect without QUIT.
	defer s.record(conn, sess)

	rw := bufio.NewReadWriter(bufio.NewReaderSize(conn, ftpMaxLine+2), bufio.NewWriter(conn))
	s.writeLine(rw, sess, "220 joro FTP ready")

	cmds := 0
	for {
		conn.SetReadDeadline(time.Now().Add(ftpIdleTimeout)) //nolint:errcheck
		line, err := s.readLine(rw)
		if err != nil {
			return
		}
		sess.transcript.WriteString("C: ")
		sess.transcript.WriteString(line)
		sess.transcript.WriteString("\r\n")

		cmds++
		if cmds > ftpMaxCommands {
			s.writeLine(rw, sess, "421 Too many commands")
			return
		}

		verb, rest := splitVerb(line)
		switch strings.ToUpper(verb) {
		case "USER":
			sess.user = rest
			sess.sawUser = true
			s.writeLine(rw, sess, "331 Password required")
		case "PASS":
			sess.pass = rest
			s.writeLine(rw, sess, "230 Login successful")
		case "SYST":
			s.writeLine(rw, sess, "215 UNIX Type: L8")
		case "FEAT":
			s.writeLines(rw, sess, []string{"211-Features:", "211 End"})
		case "PWD", "XPWD":
			s.writeLine(rw, sess, `257 "/" is current directory`)
		case "TYPE":
			s.writeLine(rw, sess, "200 Type set to "+rest)
		case "OPTS":
			s.writeLine(rw, sess, "200 OK")
		case "NOOP":
			s.writeLine(rw, sess, "200 OK")
		case "CDUP":
			s.writeLine(rw, sess, "250 OK")
		case "CWD", "XCWD", "MKD", "XMKD", "RMD", "XRMD", "DELE", "SIZE", "MDTM",
			"RETR", "STOR", "STOU", "APPE", "LIST", "NLST", "MLSD", "MLST":
			s.addPath(sess, rest)
			// Refuse the data transfer; the path argument is already captured.
			switch strings.ToUpper(verb) {
			case "CWD", "XCWD", "CDUP":
				s.writeLine(rw, sess, "250 OK")
			case "MKD", "XMKD":
				s.writeLine(rw, sess, `257 "`+rest+`" created`)
			case "RMD", "XRMD", "DELE":
				s.writeLine(rw, sess, "250 OK")
			case "SIZE":
				s.writeLine(rw, sess, "213 0")
			case "MDTM":
				s.writeLine(rw, sess, "213 20200101000000")
			default:
				s.writeLine(rw, sess, "425 Can't open data connection")
			}
		case "PASV", "EPSV", "PORT", "EPRT":
			s.writeLine(rw, sess, "502 Command not implemented")
		case "AUTH":
			s.writeLine(rw, sess, "502 Command not implemented")
		case "QUIT":
			s.writeLine(rw, sess, "221 Bye")
			return
		default:
			s.writeLine(rw, sess, "502 Command not implemented")
		}
	}
}

func (s *FTPServer) addPath(sess *ftpSession, p string) {
	p = strings.TrimSpace(p)
	if p != "" && len(sess.pathArgs) < ftpMaxPaths {
		sess.pathArgs = append(sess.pathArgs, p)
	}
}

func (s *FTPServer) readLine(rw *bufio.ReadWriter) (string, error) {
	line, err := rw.Reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > ftpMaxLine {
		return "", fmt.Errorf("ftp: line too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (s *FTPServer) writeLine(rw *bufio.ReadWriter, sess *ftpSession, line string) {
	sess.transcript.WriteString("S: ")
	sess.transcript.WriteString(line)
	sess.transcript.WriteString("\r\n")
	rw.WriteString(line + "\r\n") //nolint:errcheck
	rw.Flush()                    //nolint:errcheck
}

func (s *FTPServer) writeLines(rw *bufio.ReadWriter, sess *ftpSession, lines []string) {
	for _, l := range lines {
		sess.transcript.WriteString("S: ")
		sess.transcript.WriteString(l)
		sess.transcript.WriteString("\r\n")
		rw.WriteString(l + "\r\n") //nolint:errcheck
	}
	rw.Flush() //nolint:errcheck
}

// record correlates and stores the session. It runs once via defer; it no-ops
// if no USER was seen (bare TCP probe) or no token correlates.
func (s *FTPServer) record(conn net.Conn, sess *ftpSession) {
	if !sess.sawUser {
		return
	}

	candidates := append([]string{sess.user}, sess.pathArgs...)
	candidates = append(candidates, sess.transcript.String())
	token, err := CorrelateAny(s.store, candidates...)
	if err != nil {
		return
	}

	headers, _ := json.Marshal(map[string]string{
		"user":      sess.user,
		"pass":      sess.pass,
		"path_args": strings.Join(sess.pathArgs, ", "),
		"tls":       fmt.Sprintf("%t", sess.isTLS),
	})

	sourceIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	id := make([]byte, 16)
	rand.Read(id) //nolint:errcheck

	interaction := &Interaction{
		ID:         hex.EncodeToString(id),
		TokenID:    token.ID,
		Token:      token.Token,
		Type:       "ftp",
		SourceIP:   sourceIP,
		Timestamp:  time.Now().UTC(),
		Headers:    string(headers),
		RawRequest: base64.StdEncoding.EncodeToString(sess.transcript.Bytes()),
	}
	if err := s.store.RecordInteraction(interaction); err != nil {
		log.Printf("callback ftp: record interaction: %v", err)
		return
	}
	s.broadcast <- event.WSEvent{Type: "callback.interaction", Data: interaction}
}
