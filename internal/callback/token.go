package callback

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"regexp"
	"strings"
)

// hexRunRe matches runs of at least 16 hex characters. Callback tokens are a
// 16-char hex value, so any candidate string carrying a token contains such a
// run; we only ever use its first 16 chars.
var hexRunRe = regexp.MustCompile("[0-9a-fA-F]{16,}")

// GenerateToken creates a new token with a random 16-char hex identifier.
func GenerateToken(store *Store, name string) (*Token, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	hexStr := hex.EncodeToString(b)

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	idStr := hex.EncodeToString(id)

	return store.CreateToken(idStr, name, hexStr)
}

// Correlate extracts the token hex from a subdomain and looks it up.
// For example, given "abc123def456.cb.example.com" with domain "cb.example.com",
// it extracts "abc123def456" and looks up the token.
func Correlate(store *Store, hostname, domain string) (*Token, error) {
	hostname = strings.TrimSuffix(hostname, ".")
	domain = strings.TrimSuffix(domain, ".")

	if !strings.HasSuffix(hostname, "."+domain) {
		return nil, sql.ErrNoRows
	}

	sub := strings.TrimSuffix(hostname, "."+domain)
	// Take leftmost label
	parts := strings.SplitN(sub, ".", 2)
	label := parts[0]

	// Token is first 16 hex chars
	if len(label) < 16 {
		return nil, sql.ErrNoRows
	}
	tokenHex := strings.ToLower(label[:16])

	return store.FindTokenByHex(tokenHex)
}

// CorrelateSMTP extracts a token from an SMTP recipient address. It first
// tries the local-part (token@anything), then falls back to subdomain-style
// correlation on the domain part (anything@token.callback-domain).
func CorrelateSMTP(store *Store, rcpt, callbackDomain string) (*Token, error) {
	rcpt = strings.TrimSpace(rcpt)
	rcpt = strings.TrimPrefix(rcpt, "<")
	rcpt = strings.TrimSuffix(rcpt, ">")

	at := strings.LastIndex(rcpt, "@")
	if at < 0 {
		return nil, sql.ErrNoRows
	}
	local, domain := rcpt[:at], rcpt[at+1:]

	if len(local) >= 16 {
		tokenHex := strings.ToLower(local[:16])
		if _, err := hex.DecodeString(tokenHex); err == nil {
			if tok, err := store.FindTokenByHex(tokenHex); err == nil {
				return tok, nil
			}
		}
	}

	if callbackDomain != "" {
		return Correlate(store, domain, callbackDomain)
	}
	return nil, sql.ErrNoRows
}

// CorrelateAny scans arbitrary captured strings for hex runs that may be a
// callback token. For each [0-9a-fA-F]{16,} run it takes the first 16 chars
// and tries FindTokenByHex; the first match wins. Candidates are scanned in
// the order given (and left-to-right within each), so callers should pass the
// most specific fields (a DN, a username, a path) first and fall back to a
// full transcript or hex dump last.
//
// This correlates protocols whose payload embeds the token (e.g. an LDAP base
// DN, an FTP path or username). It cannot correlate a connection whose token
// appears only in the hostname used to reach this listener — but that hostname
// was resolved via DNS, so the existing DNS listener records that interaction
// under the "dns" type. This matches interactsh's behavior.
func CorrelateAny(store *Store, candidates ...string) (*Token, error) {
	seen := make(map[string]struct{})
	for _, cand := range candidates {
		for _, run := range hexRunRe.FindAllString(cand, -1) {
			tokenHex := strings.ToLower(run[:16])
			if _, dup := seen[tokenHex]; dup {
				continue
			}
			seen[tokenHex] = struct{}{}
			if tok, err := store.FindTokenByHex(tokenHex); err == nil {
				return tok, nil
			}
		}
	}
	return nil, sql.ErrNoRows
}
