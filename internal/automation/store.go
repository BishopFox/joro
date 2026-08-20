package automation

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/jsruntime"
)

// fileVersion is the on-disk schema version. Bump it only alongside a migration in
// normalize; unlike the project config there is no backfill machinery here, and
// there should not be — security state must not inherit "helpfully add the new
// default" semantics.
const fileVersion = 1

// flushInterval is how often last-used telemetry is written back. Mutations bypass
// it entirely and write synchronously.
const flushInterval = 30 * time.Second

var (
	ErrNotFound  = errors.New("automation: token not found")
	ErrDisabled  = errors.New("automation: token is disabled")
	ErrExpired   = errors.New("automation: token has expired")
	ErrNoTokens  = errors.New("automation: no tokens are configured")
	ErrBadSecret = errors.New("automation: unknown token")
)

// MCPState is the listener's persisted configuration. It lives in this file rather
// than the project config for the same reason the tokens do: loading a teammate's
// shared project must not bring up a listener on the operator's machine.
type MCPState struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// DefaultMCPPort is one above the UI port, so the pair is easy to remember and
// unlikely to collide with the proxy.
const DefaultMCPPort = 9091

type file struct {
	Version int      `json:"version"`
	MCP     MCPState `json:"mcp"`
	// ScriptBudget is the operator's policy for sandboxed runs: the default and the
	// maximum per field, plus the host limits. It lives here for the same reasons the
	// tokens do: a project config is published to teammates, and a user config
	// round-trips through version-gated backfill, which is exactly the wrong semantics
	// for a limit. An absent field means the runtime's own defaults and ceilings, so an
	// older file needs no migration.
	// omitzero, not omitempty: omitempty does nothing for a struct field, so an
	// unconfigured policy would be written out as three empty objects.
	ScriptBudget jsruntime.BudgetPolicy `json:"scriptBudget,omitzero"`
	Tokens       []*Token               `json:"tokens"`
}

// Store holds automation tokens, persisted to a single 0600 JSON file.
//
// Location: ~/.joro/automation.json. Deliberately not the project config, which is
// exported and published to teammates — a grant set reaching another operator's
// Joro is a real privilege transfer. Deliberately not the user config, which
// round-trips through save/load/export and version-gated normalization.
// Deliberately not ~/.joro/configs/, the namespace the UI browses, so no future
// "export all configs" can sweep credentials up. And deliberately not joro.db,
// whose OpenDB deletes its contents on open.
type Store struct {
	mu     sync.RWMutex
	path   string
	tokens map[string]*Token // by ID
	byHash map[string]*Token
	mcp    MCPState

	scriptBudget jsruntime.BudgetPolicy

	dirty atomic.Bool
}

// NewStore loads the token file, creating an empty store when it does not exist.
// A malformed file is an error rather than a silent reset: quietly discarding
// tokens would look like a revocation that never happened.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:   path,
		tokens: make(map[string]*Token),
		byHash: make(map[string]*Token),
		mcp:    MCPState{Port: DefaultMCPPort},
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("automation: reading %s: %w", path, err)
	}

	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("automation: parsing %s: %w", path, err)
	}
	if f.MCP.Port <= 0 {
		f.MCP.Port = DefaultMCPPort
	}
	s.mcp = f.MCP
	s.scriptBudget = f.ScriptBudget
	for _, t := range f.Tokens {
		if t == nil || t.ID == "" || t.Hash == "" {
			continue
		}
		normalize(t)
		s.tokens[t.ID] = t
		s.byHash[t.Hash] = t
	}
	return s, nil
}

// normalize repairs a token loaded from disk and drops any grant in a reserved
// namespace. A hand-edited or downgraded file must not be able to grant something
// the UI cannot express — this is the fourth layer of the "grant administration is
// never a capability" property, covering the case where the file itself is the
// attack surface.
func normalize(t *Token) {
	kept := t.Grants[:0]
	for _, g := range t.Grants {
		if capability.IsReserved(g) {
			log.Printf("[automation] token %s: dropping reserved grant %q", t.ID, g)
			continue
		}
		kept = append(kept, g)
	}
	t.Grants = kept
	sort.Strings(t.Grants)
	t.Grants = slices.Compact(t.Grants)

	if t.RateLimitPerMin <= 0 {
		t.RateLimitPerMin = capability.DefaultRateLimitPerMin
	}
	if t.MaxConcurrent <= 0 {
		t.MaxConcurrent = capability.DefaultMaxConcurrent
	}
	if t.MaxOutputBytes <= 0 {
		t.MaxOutputBytes = capability.DefaultMaxOutputBytes
	}
}

// Lookup resolves a presented secret to its token.
//
// The map key is a SHA-256 of the secret, so it is already a one-way function and
// map-lookup timing leaks nothing about the plaintext. The constant-time compare
// on the confirmed entry costs one call and closes the theoretical gap where a
// hash collision or a future keying change would make the map the only check.
//
// Disabled and expired produce distinct errors, which is safe: they can only fire
// on a correct secret, so they are not an oracle.
func (s *Store) Lookup(secret string) (*Token, error) {
	if secret == "" {
		return nil, ErrBadSecret
	}
	h := hashSecret(secret)

	s.mu.RLock()
	t, ok := s.byHash[h]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrBadSecret
	}
	if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) != 1 {
		return nil, ErrBadSecret
	}

	now := time.Now()
	switch {
	case t.Disabled:
		return nil, ErrDisabled
	case t.Expired(now):
		return nil, ErrExpired
	}
	return t, nil
}

// List returns every token, newest first. The returned values are copies, so a
// caller cannot mutate stored state by writing through the slice.
func (s *Store) List() []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Get returns a copy of one token.
func (s *Store) Get(id string) (Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	if !ok {
		return Token{}, false
	}
	return *t, true
}

// Count returns the number of configured tokens. The MCP listener refuses to start
// at zero: an unauthenticated MCP server on loopback is a privilege-escalation
// gadget for every other process on the machine.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}

// CreateParams is the validated input to Create.
type CreateParams struct {
	Name             string
	Grants           []string
	RequireScope     bool
	HostAllow        []string
	AllowCredentials bool
	RateLimitPerMin  int
	MaxConcurrent    int
	MaxOutputBytes   int
	ExpiresInDays    int
	CapsFingerprint  string
	GrantedAtVersion string
}

// Create mints a token and returns it alongside its one-time plaintext secret.
// The write is synchronous — security state is never debounced.
func (s *Store) Create(p CreateParams) (Token, string, error) {
	secret, hash, prefix, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}
	id, err := newTokenID()
	if err != nil {
		return Token{}, "", err
	}

	now := time.Now().UTC()
	t := &Token{
		ID:               id,
		Name:             strings.TrimSpace(p.Name),
		Hash:             hash,
		Prefix:           prefix,
		Grants:           slices.Clone(p.Grants),
		RequireScope:     p.RequireScope,
		HostAllow:        slices.Clone(p.HostAllow),
		AllowCredentials: p.AllowCredentials,
		RateLimitPerMin:  p.RateLimitPerMin,
		MaxConcurrent:    p.MaxConcurrent,
		MaxOutputBytes:   p.MaxOutputBytes,
		CreatedAt:        now,
		CapsFingerprint:  p.CapsFingerprint,
		GrantedAtVersion: p.GrantedAtVersion,
	}
	if p.ExpiresInDays > 0 {
		exp := now.AddDate(0, 0, p.ExpiresInDays)
		t.ExpiresAt = &exp
	}
	normalize(t)

	s.mu.Lock()
	s.tokens[t.ID] = t
	s.byHash[t.Hash] = t
	s.mu.Unlock()

	if err := s.flush(); err != nil {
		return Token{}, "", err
	}
	return *t, secret, nil
}

// UpdateParams carries a partial edit. Nil fields are left unchanged, matching the
// pointer-per-field convention handleUpdateSettings uses.
type UpdateParams struct {
	Name             *string
	Grants           *[]string
	RequireScope     *bool
	HostAllow        *[]string
	AllowCredentials *bool
	RateLimitPerMin  *int
	MaxConcurrent    *int
	MaxOutputBytes   *int
	Disabled         *bool
	CapsFingerprint  *string
	GrantedAtVersion *string
}

// Update applies a partial edit and persists it.
func (s *Store) Update(id string, p UpdateParams) (Token, error) {
	s.mu.Lock()
	t, ok := s.tokens[id]
	if !ok {
		s.mu.Unlock()
		return Token{}, ErrNotFound
	}
	if p.Name != nil {
		t.Name = strings.TrimSpace(*p.Name)
	}
	if p.Grants != nil {
		t.Grants = slices.Clone(*p.Grants)
	}
	if p.RequireScope != nil {
		t.RequireScope = *p.RequireScope
	}
	if p.HostAllow != nil {
		t.HostAllow = slices.Clone(*p.HostAllow)
	}
	if p.AllowCredentials != nil {
		t.AllowCredentials = *p.AllowCredentials
	}
	if p.RateLimitPerMin != nil {
		t.RateLimitPerMin = *p.RateLimitPerMin
	}
	if p.MaxConcurrent != nil {
		t.MaxConcurrent = *p.MaxConcurrent
	}
	if p.MaxOutputBytes != nil {
		t.MaxOutputBytes = *p.MaxOutputBytes
	}
	if p.Disabled != nil {
		t.Disabled = *p.Disabled
	}
	if p.CapsFingerprint != nil {
		t.CapsFingerprint = *p.CapsFingerprint
	}
	if p.GrantedAtVersion != nil {
		t.GrantedAtVersion = *p.GrantedAtVersion
	}
	normalize(t)
	out := *t
	s.mu.Unlock()

	if err := s.flush(); err != nil {
		return Token{}, err
	}
	return out, nil
}

// Rotate mints a new secret for an existing token, keeping its ID, grants and
// limits. The old secret stops working the moment the hash map is swapped, which
// happens before this returns — there is no window in which both are valid.
func (s *Store) Rotate(id string) (Token, string, error) {
	secret, hash, prefix, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}

	s.mu.Lock()
	t, ok := s.tokens[id]
	if !ok {
		s.mu.Unlock()
		return Token{}, "", ErrNotFound
	}
	delete(s.byHash, t.Hash)
	t.Hash = hash
	t.Prefix = prefix
	now := time.Now().UTC()
	t.RotatedAt = &now
	// Clear usage telemetry: it described the retired secret.
	t.LastUsedAt = nil
	t.LastUsedCapability = ""
	s.byHash[hash] = t
	out := *t
	s.mu.Unlock()

	if err := s.flush(); err != nil {
		return Token{}, "", err
	}
	return out, secret, nil
}

// Revoke deletes a token. Audit entries snapshot the token name, so activity
// history survives the row.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	t, ok := s.tokens[id]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	delete(s.tokens, id)
	delete(s.byHash, t.Hash)
	s.mu.Unlock()
	return s.flush()
}

// Touch records use in memory only, marking the file dirty for the flush loop.
//
// Writing on every invocation would put a file write on the authentication path of
// a client that can call sixty times a minute. The UI reads from memory, so
// last-used is always current regardless of flush timing; the worst case on an
// abrupt kill is half a minute of stale telemetry, which is not security state.
func (s *Store) Touch(tokenID, capabilityID string, at time.Time) {
	s.mu.Lock()
	if t, ok := s.tokens[tokenID]; ok {
		u := at.UTC()
		t.LastUsedAt = &u
		t.LastUsedCapability = capabilityID
		t.UseCount++
		s.dirty.Store(true)
	}
	s.mu.Unlock()
}

// MCP returns the persisted listener state.
func (s *Store) MCP() MCPState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mcp
}

// SetMCP persists the listener state synchronously.
func (s *Store) SetMCP(state MCPState) error {
	if state.Port <= 0 {
		state.Port = DefaultMCPPort
	}
	s.mu.Lock()
	s.mcp = state
	s.mu.Unlock()
	return s.flush()
}

// ScriptBudget returns the operator's run policy. A zero field means the runtime's own
// number for it.
func (s *Store) ScriptBudget() jsruntime.BudgetPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scriptBudget
}

// SetScriptBudget persists the run policy synchronously. Values are not clamped here —
// jsruntime holds every run to its own ceilings regardless, and the caller rejects an
// over-ceiling value so the operator is told rather than silently corrected.
func (s *Store) SetScriptBudget(b jsruntime.BudgetPolicy) error {
	s.mu.Lock()
	s.scriptBudget = b
	s.mu.Unlock()
	return s.flush()
}

// StartFlushLoop writes pending last-used telemetry every flushInterval, and once
// more on shutdown. It mirrors APIServer.StartAutoSaveLoop, including the
// dirty-check, so a store nobody uses costs one idle ticker.
func (s *Store) StartFlushLoop(ctx context.Context) {
	go func() {
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				s.flushIfDirty()
				return
			case <-t.C:
				s.flushIfDirty()
			}
		}
	}()
}

func (s *Store) flushIfDirty() {
	if !s.dirty.Load() {
		return
	}
	if err := s.flush(); err != nil {
		log.Printf("[automation] flush: %v", err)
	}
}

// flush writes the whole file atomically: a temp file in the same directory, then
// a rename, so a crash mid-write cannot leave a truncated token list that would
// read as a mass revocation.
func (s *Store) flush() error {
	s.mu.RLock()
	f := file{
		Version:      fileVersion,
		MCP:          s.mcp,
		ScriptBudget: s.scriptBudget,
		Tokens:       make([]*Token, 0, len(s.tokens)),
	}
	for _, t := range s.tokens {
		cp := *t
		f.Tokens = append(f.Tokens, &cp)
	}
	s.mu.RUnlock()
	sort.Slice(f.Tokens, func(i, j int) bool { return f.Tokens[i].CreatedAt.Before(f.Tokens[j].CreatedAt) })

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	s.dirty.Store(false)
	return nil
}
