// In-memory server + interaction storage for the Interactsh plugin.
//
// Deliberately lightweight: a slice of server records and a ring buffer of
// interactions. The plugin process is the sole owner; no persistence across
// Joro restarts (matches the pre-plugin native behaviour).
package main

import (
	"context"
	"crypto/rsa"
	"sync"
	"time"
)

const maxInteractions = 10000

type server struct {
	id            string
	serverURL     string
	authToken     string
	enabled       bool
	skipVerify    bool
	privKey       *rsa.PrivateKey
	correlationID string
	nonce         string // 13-char suffix so payload labels hit the server's 33-char correlation-ID detector
	secretKey     string
	createdAt     time.Time
	status        string // "connecting" | "connected" | "error" | "disabled"
	errMsg        string
	payloadHost   string
	cancel        context.CancelFunc
}

type storedInteraction struct {
	ID         string
	ServerID   string
	Protocol   string
	UniqueID   string
	FullID     string
	QType      string
	Method     string
	Path       string
	SourceIP   string
	Timestamp  time.Time
	RawRequest string // base64
}

type store struct {
	mu           sync.RWMutex
	servers      []*server
	interactions []storedInteraction
}

func newStore() *store {
	return &store{}
}

func (s *store) addServer(srv *server) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers = append(s.servers, srv)
}

func (s *store) getServer(id string) *server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, srv := range s.servers {
		if srv.id == id {
			return srv
		}
	}
	return nil
}

func (s *store) listServers() []*server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*server, len(s.servers))
	copy(out, s.servers)
	return out
}

func (s *store) removeServer(id string) *server {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, srv := range s.servers {
		if srv.id == id {
			s.servers = append(s.servers[:i], s.servers[i+1:]...)
			return srv
		}
	}
	return nil
}

func (s *store) recordInteraction(ix storedInteraction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interactions = append(s.interactions, ix)
	if len(s.interactions) > maxInteractions {
		s.interactions = s.interactions[len(s.interactions)-maxInteractions:]
	}
}

func (s *store) listInteractions(serverID string, offset, limit int) ([]storedInteraction, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filtered := s.interactions
	if serverID != "" {
		filtered = filtered[:0:0]
		for _, ix := range s.interactions {
			if ix.ServerID == serverID {
				filtered = append(filtered, ix)
			}
		}
	}

	// Newest-first ordering.
	total := len(filtered)
	rev := make([]storedInteraction, total)
	for i, ix := range filtered {
		rev[total-1-i] = ix
	}

	if offset >= total {
		return []storedInteraction{}, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return rev[offset:end], total
}

func (s *store) clearInteractions(serverID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if serverID == "" {
		s.interactions = nil
		return
	}
	kept := s.interactions[:0]
	for _, ix := range s.interactions {
		if ix.ServerID != serverID {
			kept = append(kept, ix)
		}
	}
	s.interactions = kept
}
