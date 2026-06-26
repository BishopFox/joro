package callback

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// newTestStore returns a Store backed by a fresh temp-file SQLite DB.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db)
}

// mkToken inserts a token and returns its 16-hex correlation value.
func mkToken(t *testing.T, s *Store) *Token {
	t.Helper()
	tok, err := GenerateToken(s, "test")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return tok
}

func TestCorrelateAny(t *testing.T) {
	s := newTestStore(t)
	tok := mkToken(t, s)

	cases := []struct {
		name       string
		candidates []string
		want       bool
	}{
		{"plain token", []string{tok.Token}, true},
		{"embedded in DN", []string{"cn=" + tok.Token + ",dc=x"}, true},
		{"uppercase", []string{"PREFIX" + bytesUpper(tok.Token) + "SUFFIX"}, true},
		{"longer hex run", []string{tok.Token + "deadbeef"}, true}, // first 16 chars match
		{"no hex", []string{"not-a-token"}, false},
		{"unknown token", []string{"0123456789abcdef"}, false},
		{"fallback order", []string{"nope", "x=" + tok.Token}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CorrelateAny(s, tc.candidates...)
			if tc.want && (err != nil || got == nil) {
				t.Fatalf("expected match, got err=%v tok=%v", err, got)
			}
			if !tc.want && err == nil {
				t.Fatalf("expected no match, got %v", got)
			}
		})
	}
}

func bytesUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func TestReadTLV(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		maxLen  int
		wantErr bool
		wantTag byte
		wantVal []byte
	}{
		{"short form", []byte{0x04, 0x03, 'a', 'b', 'c'}, 64, false, 0x04, []byte("abc")},
		{"empty value", []byte{0x04, 0x00}, 64, false, 0x04, []byte{}},
		{"long form 1 octet", append([]byte{0x04, 0x81, 0x02}, []byte("hi")...), 64, false, 0x04, []byte("hi")},
		{"oversize rejected", []byte{0x04, 0x7f}, 8, true, 0, nil},      // declares 127 > maxLen 8
		{"indefinite rejected", []byte{0x04, 0x80, 0x00}, 64, true, 0, nil},
		{"long form n>4 rejected", []byte{0x04, 0x85}, 64, true, 0, nil},
		{"truncated value", []byte{0x04, 0x04, 'a', 'b'}, 64, true, 0, nil}, // declares 4, only 2 present
		{"high tag rejected", []byte{0x1f, 0x01, 0x00}, 64, true, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tag, val, _, err := readTLV(bufio.NewReader(bytes.NewReader(tc.in)), tc.maxLen)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got tag=%#x val=%q", tag, val)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tag != tc.wantTag || !bytes.Equal(val, tc.wantVal) {
				t.Fatalf("got tag=%#x val=%q, want tag=%#x val=%q", tag, val, tc.wantTag, tc.wantVal)
			}
		})
	}
}

// ldapSearch builds a minimal LDAP SearchRequest LDAPMessage with the given
// base DN (messageID = 2).
func ldapSearch(baseDN string) []byte {
	// SearchRequest body: baseObject OCTET STRING + scope ENUMERATED +
	// derefAliases ENUMERATED + sizeLimit/timeLimit INTEGERs + typesOnly BOOL +
	// filter (present:objectClass) + attrs SEQUENCE. We only need a valid-enough
	// prefix: baseObject is read first.
	base := ber(berOctetString, []byte(baseDN))
	scope := []byte{0x0a, 0x01, 0x00}        // ENUMERATED baseObject
	deref := []byte{0x0a, 0x01, 0x00}        // ENUMERATED neverDeref
	sizeL := []byte{0x02, 0x01, 0x00}        // sizeLimit 0
	timeL := []byte{0x02, 0x01, 0x00}        // timeLimit 0
	typesO := []byte{0x01, 0x01, 0x00}       // typesOnly false
	filter := []byte{0x87, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's'} // present filter
	attrs := ber(berSequence, nil)
	body := bytes.Join([][]byte{base, scope, deref, sizeL, timeL, typesO, filter, attrs}, nil)
	op := ber(ldapSearchRequest, body)
	inner := append(ber(berInteger, []byte{0x02}), op...) // messageID = 2
	return ber(berSequence, inner)
}

func TestLDAPRoundTrip(t *testing.T) {
	s := newTestStore(t)
	tok := mkToken(t, s)
	bcast := make(chan any, 4)
	srv := NewLDAPServer(s, bcast, "127.0.0.1", 0, 0, nil)

	clientConn, serverConn := net.Pipe()
	go srv.handleConnection(serverConn, false)

	clientConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	baseDN := "cn=" + tok.Token + ",dc=joro"
	if _, err := clientConn.Write(ldapSearch(baseDN)); err != nil {
		t.Fatalf("write search: %v", err)
	}

	// Read the response and assert it's a valid SearchResultDone with success.
	resp := make([]byte, 256)
	n, err := clientConn.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	tag, body, _, err := readTLV(bufio.NewReader(bytes.NewReader(resp[:n])), ldapMaxMessage)
	if err != nil || tag != berSequence {
		t.Fatalf("response not a SEQUENCE: tag=%#x err=%v", tag, err)
	}
	seq := bufio.NewReader(bytes.NewReader(body))
	if mt, _, _, _ := readTLV(seq, 8); mt != berInteger {
		t.Fatalf("expected messageID INTEGER, got %#x", mt)
	}
	opTag, opBody, _, _ := readTLV(seq, ldapMaxMessage)
	if opTag != ldapSearchDone {
		t.Fatalf("expected SearchResultDone %#x, got %#x", ldapSearchDone, opTag)
	}
	if len(opBody) < 3 || opBody[0] != 0x0a || opBody[2] != 0x00 {
		t.Fatalf("expected resultCode success, got %v", opBody)
	}

	// Close so the deferred record() runs, then expect a broadcast.
	clientConn.Close() //nolint:errcheck
	select {
	case <-bcast:
	case <-time.After(2 * time.Second):
		t.Fatal("no broadcast after search")
	}

	// Verify it was persisted with the right base DN and type.
	items, total, err := s.ListInteractions("", 0, 10)
	if err != nil || total != 1 {
		t.Fatalf("expected 1 interaction, got total=%d err=%v", total, err)
	}
	if items[0].Type != "ldap" || items[0].QueryName != baseDN {
		t.Fatalf("unexpected interaction: type=%q queryName=%q", items[0].Type, items[0].QueryName)
	}
	if items[0].Token != tok.Token {
		t.Fatalf("wrong token correlated: %q", items[0].Token)
	}
}

func TestLDAPGarbageDoesNotPanicOrRecord(t *testing.T) {
	s := newTestStore(t)
	bcast := make(chan any, 4)
	srv := NewLDAPServer(s, bcast, "127.0.0.1", 0, 0, nil)

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() { srv.handleConnection(serverConn, false); close(done) }()

	clientConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	// Random non-LDAP bytes (e.g. a TLS ClientHello starts 0x16).
	clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00}) //nolint:errcheck
	clientConn.Close()                                                                   //nolint:errcheck

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConnection did not return on garbage input")
	}
	if _, total, _ := s.ListInteractions("", 0, 10); total != 0 {
		t.Fatalf("expected no interaction for garbage, got %d", total)
	}
}

func TestFTPCorrelation(t *testing.T) {
	s := newTestStore(t)
	tok := mkToken(t, s)
	bcast := make(chan any, 4)
	srv := NewFTPServer(s, bcast, "127.0.0.1", 0, 0, nil)

	clientConn, serverConn := net.Pipe()
	go srv.handleConnection(serverConn, false)

	br := bufio.NewReader(clientConn)
	clientConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	readReply(t, br)                                         // 220 banner

	send := func(cmd string) {
		clientConn.Write([]byte(cmd + "\r\n")) //nolint:errcheck
		readReply(t, br)
	}
	send("USER " + tok.Token)
	send("CWD /loot")
	send("QUIT")

	select {
	case <-bcast:
	case <-time.After(2 * time.Second):
		t.Fatal("no broadcast for FTP session")
	}

	items, total, err := s.ListInteractions("", 0, 10)
	if err != nil || total != 1 {
		t.Fatalf("expected 1 interaction, got total=%d err=%v", total, err)
	}
	if items[0].Type != "ftp" || items[0].Token != tok.Token {
		t.Fatalf("unexpected interaction: type=%q token=%q", items[0].Type, items[0].Token)
	}
	raw, _ := base64.StdEncoding.DecodeString(items[0].RawRequest)
	if !bytes.Contains(raw, []byte("USER "+tok.Token)) {
		t.Fatalf("transcript missing USER command: %q", raw)
	}
}

func readReply(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return line
}
