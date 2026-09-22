package apiscan

import (
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/apispec"
)

// Store holds runs in memory, bounded like fuzzer.Store. Runs are session state
// and never reach the project file.
type Store struct {
	mu   sync.RWMutex
	runs []*Run
	max  int
}

// NewStore creates an empty run store.
func NewStore() *Store { return &Store{max: MaxRuns} }

// Add registers a run, evicting the oldest finished one when full. A running run
// is never evicted: its workers hold a pointer to it, and dropping it from the
// store would only make it unreachable, not stop it.
func (s *Store) Add(r *Run) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.runs) >= s.max {
		for i, old := range s.runs {
			if old.Status() != StatusRunning {
				s.runs = append(s.runs[:i], s.runs[i+1:]...)
				break
			}
		}
	}
	s.runs = append(s.runs, r)
}

// Get returns a run by ID, or nil.
func (s *Store) Get(id string) *Run {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.runs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// List returns every run, newest first.
func (s *Store) List() []*Run {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Run, len(s.runs))
	for i, r := range s.runs {
		out[len(s.runs)-1-i] = r
	}
	return out
}

// Delete removes a run, reporting whether it was found.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.runs {
		if r.ID == id {
			s.runs = append(s.runs[:i], s.runs[i+1:]...)
			return true
		}
	}
	return false
}

// StoredSpec is a parsed document plus where it came from.
type StoredSpec struct {
	Spec     *apispec.Spec `json:"spec"`
	LoadedAt time.Time     `json:"loadedAt"`

	// Source is the original bytes, kept so the operator can read the document
	// they are working against. It is served by its own endpoint rather than
	// riding on every spec response, because it is routinely megabytes.
	Source []byte `json:"-"`
}

// SpecStore holds parsed documents and the auth profiles defined against them.
//
// In memory only. A document fetched by URL went through the proxy and is
// therefore already in History, so persisting it would store it twice; and
// profiles hold credentials, which is why webhooks.json's secrets are kept out
// of the project file too.
type SpecStore struct {
	mu       sync.RWMutex
	specs    []*StoredSpec
	profiles map[string][]Profile // keyed by spec ID
	max      int
}

// NewSpecStore creates an empty spec store.
func NewSpecStore() *SpecStore {
	return &SpecStore{profiles: map[string][]Profile{}, max: MaxSpecs}
}

// Put stores a parsed document, replacing an existing one with the same ID. The
// ID is a hash of the source bytes, so re-loading an unchanged document keeps
// the profiles already defined against it.
//
// The same ID does not imply the same generated defaults: one source parsed
// under two sets of apispec.Placeholders yields two Specs sharing an ID, and the
// last Put wins. Anything that re-parses stored source therefore has to mean it
// — which is why discovery only Puts a document not already held.
func (s *SpecStore) Put(spec *apispec.Spec, source []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.specs {
		if existing.Spec.ID == spec.ID {
			// Moved to the back, not updated in place. Eviction below takes
			// specs[0], so position is the eviction order; refreshing LoadedAt
			// without moving the entry left a document the operator reloads
			// constantly still first in line to be dropped — out from under the
			// tab still using it, whose every later render and scan then 404s.
			s.specs = append(append(s.specs[:i:i], s.specs[i+1:]...),
				&StoredSpec{Spec: spec, Source: source, LoadedAt: time.Now()})
			return
		}
	}
	if len(s.specs) >= s.max {
		evicted := s.specs[0]
		delete(s.profiles, evicted.Spec.ID)
		s.specs = s.specs[1:]
	}
	s.specs = append(s.specs, &StoredSpec{Spec: spec, Source: source, LoadedAt: time.Now()})
}

// Get returns a stored document by ID, or nil.
func (s *SpecStore) Get(id string) *StoredSpec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, stored := range s.specs {
		if stored.Spec.ID == id {
			return stored
		}
	}
	return nil
}

// List returns every stored document, newest first.
func (s *SpecStore) List() []*StoredSpec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*StoredSpec, len(s.specs))
	for i, stored := range s.specs {
		out[len(s.specs)-1-i] = stored
	}
	return out
}

// Delete removes a document and the profiles defined against it.
func (s *SpecStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, stored := range s.specs {
		if stored.Spec.ID == id {
			s.specs = append(s.specs[:i], s.specs[i+1:]...)
			delete(s.profiles, id)
			return true
		}
	}
	return false
}

// SetProfiles replaces the profile set for one document.
func (s *SpecStore) SetProfiles(specID string, profiles []Profile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[specID] = profiles
}

// Profiles returns a copy of the profile set for one document, credentials
// included. Callers that serialize these must strip Auth; it is json:"-" so the
// encoder does that on its own.
func (s *SpecStore) Profiles(specID string) []Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Profile, len(s.profiles[specID]))
	copy(out, s.profiles[specID])
	return out
}

// Clear drops every document and profile, for a project switch.
func (s *SpecStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.specs = nil
	s.profiles = map[string][]Profile{}
}
