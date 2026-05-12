package proxy

import (
	"strings"
	"sync"
)

// WSStore is a thread-safe in-memory ring buffer of captured WebSocket messages.
type WSStore struct {
	mu      sync.RWMutex
	items   []*CapturedWSMessage
	maxSize int
}

// NewWSStore creates a WSStore with the given max capacity.
func NewWSStore(maxSize int) *WSStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &WSStore{
		items:   make([]*CapturedWSMessage, 0, 256),
		maxSize: maxSize,
	}
}

// Add appends a message, evicting the oldest if at capacity.
func (s *WSStore) Add(m *CapturedWSMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= s.maxSize {
		s.items = s.items[1:]
	}
	s.items = append(s.items, m)
}

// WSMessageFilter holds optional filter criteria.
type WSMessageFilter struct {
	Host   string
	Offset int
	Limit  int
}

// List returns a filtered, paginated slice along with total count.
func (s *WSStore) List(f WSMessageFilter) ([]*CapturedWSMessage, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*CapturedWSMessage
	for _, m := range s.items {
		if f.Host != "" && !strings.Contains(strings.ToLower(m.Host), strings.ToLower(f.Host)) {
			continue
		}
		filtered = append(filtered, m)
	}

	total := len(filtered)
	if f.Offset >= total {
		return []*CapturedWSMessage{}, total
	}

	end := f.Offset + f.Limit
	if f.Limit <= 0 || end > total {
		end = total
	}
	return filtered[f.Offset:end], total
}

// Clear removes all stored messages.
func (s *WSStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = s.items[:0]
}
