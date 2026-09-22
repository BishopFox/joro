package chain

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Store holds the live chain set.
//
// In memory, backed by the project file rather than a file of its own. A chain is
// engagement data — it describes one application's checkout, and it is useful to
// a teammate who opens the same project — which is the opposite of the case
// internal/trigger's store makes for living in ~/.joro: a trigger is referenced
// by installed automations, which are machine-global because executable code must
// not travel in a project file. Nothing installed references a chain.
type Store struct {
	mu     sync.RWMutex
	chains []*Chain

	// rev changes on every mutation. The autosave signature needs it because an
	// edit to a chain's bindings leaves the chain count identical, and a count
	// is all the rest of that signature has to go on.
	rev uint64
}

// NewStore creates an empty store.
func NewStore() *Store { return &Store{} }

// List returns every chain, oldest first, as clones.
func (s *Store) List() []*Chain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Chain, len(s.chains))
	for i, c := range s.chains {
		out[i] = c.Clone()
	}
	return out
}

// Get returns a clone of one chain, or nil.
func (s *Store) Get(id string) *Chain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.chains {
		if c.ID == id {
			return c.Clone()
		}
	}
	return nil
}

// Count reports how many chains are held, for the autosave signature.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.chains)
}

// Revision reports a counter that changes whenever a chain does, so autosave can
// notice an edit that leaves the count the same.
func (s *Store) Revision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rev
}

// Create validates and stores a new chain, assigning its id.
func (s *Store) Create(c *Chain) (*Chain, error) {
	c.Normalize()
	if err := Validate(c); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.chains) >= MaxChains {
		return nil, fmt.Errorf("this project already holds %d chains, the limit", MaxChains)
	}
	c.ID = newID()
	c.CreatedAt = time.Now()
	c.UpdatedAt = c.CreatedAt
	s.chains = append(s.chains, c)
	s.rev++
	return c.Clone(), nil
}

// Update replaces a chain's contents. The id is frozen.
func (s *Store) Update(id string, c *Chain) (*Chain, error) {
	c.Normalize()
	if err := Validate(c); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, old := range s.chains {
		if old.ID != id {
			continue
		}
		c.ID = id
		c.CreatedAt = old.CreatedAt
		c.UpdatedAt = time.Now()
		s.chains[i] = c
		s.rev++
		return c.Clone(), nil
	}
	return nil, fmt.Errorf("no chain %s", id)
}

// Delete removes a chain, reporting whether it was found.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.chains {
		if c.ID == id {
			s.chains = append(s.chains[:i], s.chains[i+1:]...)
			s.rev++
			return true
		}
	}
	return false
}

// ReplaceAll swaps the whole set, which is what loading a project does.
//
// Unvalidated on purpose, matching the read-path rule in Validate's doc: a chain
// a hand edit pushed past a bound has to appear in the list so it can be fixed.
func (s *Store) ReplaceAll(chains []*Chain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(chains) > MaxChains {
		chains = chains[:MaxChains]
	}
	s.chains = make([]*Chain, 0, len(chains))
	for _, c := range chains {
		if c == nil {
			continue
		}
		c.Normalize()
		s.chains = append(s.chains, c)
	}
	s.rev++
}

// Clear drops every chain, for a project switch.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chains = nil
	s.rev++
}

// New assembles a chain from recorded exchanges, assigning step ids and
// labels. Raws over the caps are truncated rather than refused: a step whose
// upload body was trimmed still replays usefully, and refusing would lose the
// workflow over one request.
func New(name string, steps []Step) *Chain {
	c := &Chain{Name: name}
	for i, s := range steps {
		s.ID = "s" + strconv.Itoa(i+1)
		if s.Label == "" {
			s.Label = Label(s.ReqRaw)
		}
		if len(s.ReqRaw) > MaxStepBytes {
			s.ReqRaw = s.ReqRaw[:MaxStepBytes]
		}
		if len(s.RespRaw) > MaxStepRespBytes {
			s.RespRaw = s.RespRaw[:MaxStepRespBytes]
		}
		c.Steps = append(c.Steps, s)
	}
	c.Normalize()
	return c
}

// Reindex assigns positional step ids and rewrites every reference to them.
//
// Called when steps arrive without ids — a chain built from History, or one being
// appended to — never on a plain update. An update must leave ids alone: after a
// drag-reorder the canvas sends the same steps in a new order, and renumbering
// them there would repoint every binding at whichever step landed in its slot.
//
// Each step's old id is read once, immediately before its new one is written, so
// a new id colliding with one a later step still holds does not matter. Steps
// with no id, and the second of a duplicated pair, contribute nothing to the
// remap: there is no reference to rewrite, and letting them share a key would
// make every one of them resolve to the same step.
func Reindex(c *Chain) {
	remap := make(map[string]string, len(c.Steps))
	for i := range c.Steps {
		want := "s" + strconv.Itoa(i+1)
		if old := c.Steps[i].ID; old != "" {
			if _, dup := remap[old]; !dup {
				remap[old] = want
			}
		}
		c.Steps[i].ID = want
	}
	for i := range c.Bindings {
		if v, ok := remap[c.Bindings[i].FromStep]; ok {
			c.Bindings[i].FromStep = v
		}
		if v, ok := remap[c.Bindings[i].ToStep]; ok {
			c.Bindings[i].ToStep = v
		}
	}
	if v, ok := remap[c.GoalStepID]; ok {
		c.GoalStepID = v
	}
}
