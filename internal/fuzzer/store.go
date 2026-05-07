package fuzzer

import "sync"

// Store holds fuzzer campaigns in memory.
type Store struct {
	mu        sync.RWMutex
	campaigns []*Campaign
	maxItems  int
}

// NewStore creates a new in-memory campaign store.
func NewStore() *Store {
	return &Store{maxItems: 50}
}

// Add registers a new campaign.
func (s *Store) Add(c *Campaign) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.campaigns) >= s.maxItems {
		// Evict the oldest completed/stopped campaign.
		for i, old := range s.campaigns {
			if old.Status != StatusRunning {
				s.campaigns = append(s.campaigns[:i], s.campaigns[i+1:]...)
				break
			}
		}
	}
	s.campaigns = append(s.campaigns, c)
}

// Get returns a campaign by ID, or nil.
func (s *Store) Get(id string) *Campaign {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.campaigns {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// List returns all campaigns (newest first).
func (s *Store) List() []*Campaign {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Campaign, len(s.campaigns))
	for i, c := range s.campaigns {
		out[len(s.campaigns)-1-i] = c
	}
	return out
}

// Delete removes a campaign by ID. Returns true if found and removed.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.campaigns {
		if c.ID == id {
			s.campaigns = append(s.campaigns[:i], s.campaigns[i+1:]...)
			return true
		}
	}
	return false
}
