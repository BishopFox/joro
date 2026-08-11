// Package automation holds the bearer tokens that authenticate automation
// clients, and the grant sets that bound what each one may do.
//
// It imports internal/capability to build a Principal. The reverse import would be
// a cycle, which is what makes token administration unreachable from a capability
// handler: the types simply do not exist in that direction. Grant editing is a
// UI-only operation reached through the same-origin REST API, never through the
// MCP surface.
package automation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/capability"
)

// secretPrefix makes a leaked token recognizable in a config file, a shell history
// or a screenshot, and greppable across an operator's environment.
const secretPrefix = "joro_"

// Token is one bearer credential handed to one automation client.
//
// There is deliberately no secret field. The plaintext exists only in the response
// to create and rotate, carried by a separate type, so no read path can regress
// into leaking it.
type Token struct {
	ID     string `json:"id"` // "tok_" + 16 hex; stable, safe to log
	Name   string `json:"name"`
	Hash   string `json:"hash"`   // hex sha256 of the secret
	Prefix string `json:"prefix"` // first 8 chars after secretPrefix, for display

	// Grants is a fully expanded, sorted list of capability IDs. Wildcards do not
	// exist here by design: "http.*" written today would silently grant a
	// send-capable capability shipped in a later version, and this tool's
	// capability surface will grow precisely toward things that touch a target.
	// The UI offers class-level checkboxes and presets that check boxes; they
	// never store a pattern.
	Grants []string `json:"grants"`

	// RequireScope makes sends fail closed unless Joro's scope is enabled, has at
	// least one rule, and matches. HostAllow ANDs with that; it never widens.
	RequireScope bool     `json:"requireScope"`
	HostAllow    []string `json:"hostAllow,omitempty"`

	RateLimitPerMin int `json:"rateLimitPerMin"`
	MaxConcurrent   int `json:"maxConcurrent"`
	MaxOutputBytes  int `json:"maxOutputBytes"`

	Disabled  bool       `json:"disabled"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	RotatedAt *time.Time `json:"rotatedAt,omitempty"`

	LastUsedAt         *time.Time `json:"lastUsedAt,omitempty"`
	LastUsedCapability string     `json:"lastUsedCapability,omitempty"`
	UseCount           int64      `json:"useCount"`

	// CapsFingerprint is the registry fingerprint as of the last grant review, and
	// GrantedAtVersion the Joro version then. Together they let the UI say "three
	// new capabilities exist" without ever granting one implicitly.
	CapsFingerprint  string `json:"capsFingerprint,omitempty"`
	GrantedAtVersion string `json:"grantedAtVersion,omitempty"`
}

// Limit bounds accepted from the REST layer. The UI is not a control, so these are
// enforced server-side too.
const (
	MinRateLimitPerMin = 1
	MaxRateLimitPerMin = 600
	MinMaxConcurrent   = 1
	MaxMaxConcurrent   = 16
	MinOutputBytes     = 4 << 10
	MaxOutputBytes     = 16 << 20
	MaxNameLen         = 64
	MaxExpiryDays      = 365
)

// Expired reports whether the token's expiry has passed.
func (t *Token) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && now.After(*t.ExpiresAt)
}

// Usable reports whether the token may authenticate right now.
func (t *Token) Usable(now time.Time) bool {
	return !t.Disabled && !t.Expired(now)
}

// SendsTraffic reports whether any grant emits traffic to a target, which is what
// the UI's scope banner keys off. reg may be nil, in which case this is false.
func (t *Token) SendsTraffic(reg *capability.Registry) bool {
	if reg == nil {
		return false
	}
	for _, id := range t.Grants {
		if c, ok := reg.Get(id); ok && c.SendsTraffic {
			return true
		}
	}
	return false
}

// Principal projects a Token into the value the registry guards against. This is
// the only bridge between the two packages, and it flows one way.
func (t *Token) Principal() capability.Principal {
	grants := make(map[string]struct{}, len(t.Grants))
	for _, g := range t.Grants {
		grants[g] = struct{}{}
	}
	return capability.Principal{
		TokenID:         t.ID,
		TokenName:       t.Name,
		Grants:          grants,
		RequireScope:    t.RequireScope,
		HostAllow:       slices.Clone(t.HostAllow),
		RateLimitPerMin: t.RateLimitPerMin,
		MaxConcurrent:   t.MaxConcurrent,
		MaxOutputBytes:  t.MaxOutputBytes,
	}
}

// newSecret mints a bearer secret: 32 bytes of crypto/rand, base64url without
// padding, so it survives a JSON config file and a query string unescaped.
//
// It is hashed with a bare SHA-256 and no KDF. That is correct here rather than
// lazy: the input is 256 bits of uniform randomness, so there is no guessable
// preimage to slow an attacker down against, and a KDF would only add latency to
// the authentication path and a dependency to the build.
func newSecret() (secret, hash, prefix string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", err
	}
	body := base64.RawURLEncoding.EncodeToString(buf)
	secret = secretPrefix + body
	hash = hashSecret(secret)
	prefix = body[:8]
	return secret, hash, prefix, nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

func newTokenID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "tok_" + hex.EncodeToString(buf), nil
}
