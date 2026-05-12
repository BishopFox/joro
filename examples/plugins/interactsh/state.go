// Project-config state persistence for the Interactsh plugin.
//
// Interactsh state is engagement-scoped (per-target correlation IDs are
// meaningless outside the project they were created in), so we implement
// sdk.ProjectStatefulPlugin rather than sdk.UserStatefulPlugin.
//
// The correlation ID + nonce + secret key + RSA private key together form a
// session handle with the remote interactsh server. Restoring them verbatim
// and resuming polling lets an operator reopen a project and keep receiving
// callbacks against the same payload URL — provided the remote server still
// retains the session (usually ~24h on oast.live, longer on self-hosted).
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/BishopFox/joro/sdk"
)

// Compile-time assertion: *provider satisfies sdk.ProjectStatefulPlugin.
// If the SDK interface drifts, this line fails to compile before runtime.
var _ sdk.ProjectStatefulPlugin = (*provider)(nil)

type persistedState struct {
	Version int               `json:"version"`
	Servers []persistedServer `json:"servers"`
}

type persistedServer struct {
	ID            string    `json:"id"`
	ServerURL     string    `json:"serverUrl"`
	AuthToken     string    `json:"authToken,omitempty"`
	Enabled       bool      `json:"enabled"`
	SkipVerify    bool      `json:"skipVerify,omitempty"`
	PrivKeyPEM    string    `json:"privKeyPem"`
	CorrelationID string    `json:"correlationId"`
	Nonce         string    `json:"nonce"`
	SecretKey     string    `json:"secretKey"`
	CreatedAt     time.Time `json:"createdAt"`
	PayloadHost   string    `json:"payloadHost"`
}

// ExportProjectState snapshots every live server into an opaque byte blob.
// Runtime-only fields (status/errMsg/cancel) are intentionally dropped —
// they're reconstructed on ImportProjectState.
func (p *provider) ExportProjectState() ([]byte, error) {
	servers := p.store.listServers()
	state := persistedState{
		Version: 1,
		Servers: make([]persistedServer, 0, len(servers)),
	}
	for _, srv := range servers {
		if srv.privKey == nil {
			// Skip half-registered servers — without the key the entry is
			// useless on restore.
			continue
		}
		keyDER := x509.MarshalPKCS1PrivateKey(srv.privKey)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
		state.Servers = append(state.Servers, persistedServer{
			ID:            srv.id,
			ServerURL:     srv.serverURL,
			AuthToken:     srv.authToken,
			Enabled:       srv.enabled,
			SkipVerify:    srv.skipVerify,
			PrivKeyPEM:    string(keyPEM),
			CorrelationID: srv.correlationID,
			Nonce:         srv.nonce,
			SecretKey:     srv.secretKey,
			CreatedAt:     srv.createdAt,
			PayloadHost:   srv.payloadHost,
		})
	}
	return json.Marshal(state)
}

// ImportProjectState replaces the in-memory server list with the contents of
// the supplied blob and resumes polling for every enabled server. Does NOT
// re-register with the remote — correlation IDs are preserved so pending
// interactions still decrypt.
//
// Before restoring, any currently-registered servers are deregistered and
// their poll goroutines cancelled so there's no leak across a load.
func (p *provider) ImportProjectState(data []byte) error {
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal state: %w", err)
	}

	// Tear down whatever is currently loaded. This matters when an operator
	// already has instances running and loads a different project — we don't
	// want the two sets to accumulate.
	for _, existing := range p.store.listServers() {
		if existing.cancel != nil {
			existing.cancel()
		}
		p.store.removeServer(existing.id)
		p.store.clearInteractions(existing.id)
	}

	for _, ps := range state.Servers {
		priv, err := parseRSAPrivKey(ps.PrivKeyPEM)
		if err != nil {
			// Skip this server but keep going — one corrupt blob shouldn't
			// block the rest of the project.
			continue
		}
		srv := &server{
			id:            ps.ID,
			serverURL:     ps.ServerURL,
			authToken:     ps.AuthToken,
			enabled:       ps.Enabled,
			skipVerify:    ps.SkipVerify,
			privKey:       priv,
			correlationID: ps.CorrelationID,
			nonce:         ps.Nonce,
			secretKey:     ps.SecretKey,
			createdAt:     ps.CreatedAt,
			payloadHost:   ps.PayloadHost,
			status:        "connecting",
		}
		if !srv.enabled {
			srv.status = "disabled"
		}
		p.store.addServer(srv)
		if srv.enabled {
			p.mu.Lock()
			p.startPoll(srv)
			p.mu.Unlock()
		}
	}
	return nil
}

func parseRSAPrivKey(p string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
