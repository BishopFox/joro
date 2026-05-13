package callback

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"strings"
)

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
