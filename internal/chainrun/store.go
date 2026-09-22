package chainrun

import "sync"

// Store holds runs in memory, bounded like apiscan.Store. Runs are session state
// and never reach the project file.
type Store struct {
	mu   sync.RWMutex
	runs []*Run
}

// NewStore creates an empty run store.
func NewStore() *Store { return &Store{} }

// Add registers a run, evicting the oldest finished one when full. A running run
// is never evicted: Execute holds a pointer to it, and dropping it from the store
// would only make it unreachable, not stop it.
func (s *Store) Add(r *Run) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.runs) >= MaxRuns {
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

// Running returns the run currently in flight, or nil.
//
// A chain run holds the application's state for its whole duration, so a second
// concurrent run would interleave with it and both would produce verdicts
// describing the interleaving rather than the application. The handler uses this
// to refuse rather than queue, because a queue would hide that constraint behind
// a wait.
func (s *Store) Running() *Run {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.runs {
		if r.Status() == StatusRunning {
			return r
		}
	}
	return nil
}

// AddIfIdle adds a run only if none is in flight, returning the run that blocked
// it or nil on success.
//
// One lock for the test and the insert: Running then Add leaves a gap two
// requests can both pass through, which is the interleaving the single-run rule
// exists to prevent.
func (s *Store) AddIfIdle(r *Run) *Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, old := range s.runs {
		if old.Status() == StatusRunning {
			return old
		}
	}
	if len(s.runs) >= MaxRuns {
		for i, old := range s.runs {
			if old.Status() != StatusRunning {
				s.runs = append(s.runs[:i], s.runs[i+1:]...)
				break
			}
		}
	}
	s.runs = append(s.runs, r)
	return nil
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

// Clear stops and drops every run, for a project switch.
func (s *Store) Clear() {
	s.mu.Lock()
	runs := s.runs
	s.runs = nil
	s.mu.Unlock()
	for _, r := range runs {
		r.Stop()
	}
}
