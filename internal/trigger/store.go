package trigger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/BishopFox/joro/internal/atomicfile"
)

// The custom trigger store: one file, ~/.joro/triggers.json.
//
// Global rather than per-project, and that is forced rather than chosen. Installed
// automations are machine-global — a project config is published to teammates and
// executable code must not travel with it — and an automation references a trigger by id.
// A per-project store would resolve that reference on one engagement and dangle on the
// next, with no notification path, which is exactly the trigger that silently never fires
// this package exists to avoid. The store follows the thing that references it.
//
// Not ~/.joro/configs/ either: that is the namespace the UI browses and loads whole, and
// a trigger is not something an operator switches between. Not the project file, and not
// automation.json, which is the security store.

// FileVersion is the on-disk schema version. Bump it only alongside a migration; there is
// no backfill machinery here and there should not be, for the same reason automation.json
// has none — a definition other things reference must not inherit "helpfully add the new
// default" semantics.
const FileVersion = 1

// MaxTriggers bounds the file. Generous, because a trigger is small and an engagement
// might reasonably want dozens; bounded at all because the whole set is compiled on every
// change and held in memory by the dispatcher.
const MaxTriggers = 500

var (
	// ErrNotFound means no custom trigger has that id.
	ErrNotFound = errors.New("no such trigger")
	// ErrExists means one already does.
	ErrExists = errors.New("a trigger with that id already exists")
	// ErrInUse means an automation still references it.
	ErrInUse = errors.New("this trigger is in use")
)

type file struct {
	Version  int        `json:"version"`
	Triggers []*Trigger `json:"triggers"`
}

// Store holds the operator's custom triggers.
type Store struct {
	mu   sync.RWMutex
	path string
	byID map[string]*Trigger

	// rev increments on every mutation so a consumer that caches the compiled set — the
	// dispatcher — can reload only when something actually changed rather than
	// recompiling every trigger on a 250ms tick. The same idiom jsautomation.Store and
	// detect.Store both use.
	rev atomic.Uint64
}

// NewStore opens the trigger file, creating nothing until the first write.
//
// A file that will not parse is a hard error, not a silent empty set. The two failures
// look nothing alike from the operator's side: an empty store makes every referencing
// automation read as unconditional and start firing on raw events, where a loud failure
// leaves them switched off and says why.
func NewStore(dir string) (*Store, error) {
	s := &Store{
		path: filepath.Join(dir, "triggers.json"),
		byID: map[string]*Trigger{},
	}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.path, err)
	}

	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	for _, t := range f.Triggers {
		if t == nil || t.ID == "" {
			continue
		}
		t.Normalize()
		t.Builtin = false
		// Deliberately not validated here. A trigger this build cannot read still has to
		// list, so the operator can see it and go fix it — Compile poisons it and Problem
		// says why. Refusing it at load would make it vanish instead, which is the same
		// mistake as validating a manifest on the load path.
		s.byID[t.ID] = t
	}
	return s, nil
}

// Revision reports the mutation counter.
func (s *Store) Revision() uint64 { return s.rev.Load() }

// List returns every custom trigger, sorted by name, each with Problem filled in.
func (s *Store) List() []Trigger {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Trigger, 0, len(s.byID))
	for _, t := range s.byID {
		out = append(out, withProblem(*t))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one custom trigger.
func (s *Store) Get(id string) (Trigger, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byID[id]
	if !ok {
		return Trigger{}, ErrNotFound
	}
	return withProblem(*t), nil
}

// Resolve returns the trigger a reference names, whether built-in or custom.
//
// A reference that resolves to nothing is an error rather than a permissive default. The
// caller is the dispatcher, and the only safe reading of "the trigger this automation
// waits for is gone" is that it does not run.
func (s *Store) Resolve(ref string) (Trigger, error) {
	if IsBuiltin(ref) {
		for _, t := range BuiltinTriggers() {
			if t.ID == ref {
				return t, nil
			}
		}
	}
	return s.Get(ref)
}

// All returns the built-ins followed by the custom triggers, which is the order the UI
// lists them in.
func (s *Store) All() []Trigger {
	return append(BuiltinTriggers(), s.List()...)
}

// withProblem fills in why a stored trigger will not fire, leaving Problem empty when it
// will. Computed on the way out rather than stored, so it can never disagree with what
// the compiler actually does.
func withProblem(t Trigger) Trigger {
	if c := Compile(&t); c.Poisoned {
		t.Problem = c.Reason
		return t
	}
	if orphans := t.Graph.Orphans(); len(orphans) > 0 {
		t.Problem = fmt.Sprintf("%d node(s) are not connected to the run node and do nothing: %v",
			len(orphans), orphans)
	}
	return t
}

// Create stores a new trigger.
func (s *Store) Create(t Trigger) (Trigger, error) {
	t.Normalize()
	t.Builtin, t.Problem = false, ""
	if err := t.Validate(); err != nil {
		return Trigger{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.byID[t.ID]; dup {
		return Trigger{}, ErrExists
	}
	if len(s.byID) >= MaxTriggers {
		return Trigger{}, fmt.Errorf("this Joro holds %d triggers, which is the limit", MaxTriggers)
	}
	s.byID[t.ID] = &t
	if err := s.flushLocked(); err != nil {
		delete(s.byID, t.ID)
		return Trigger{}, err
	}
	s.rev.Add(1)
	return withProblem(t), nil
}

// Update replaces a stored trigger. The id is frozen, as an automation's is: renaming it
// would silently unhook every automation pointing at it.
func (s *Store) Update(id string, t Trigger) (Trigger, error) {
	t.ID = id
	t.Normalize()
	t.Builtin, t.Problem = false, ""
	if err := t.Validate(); err != nil {
		return Trigger{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.byID[id]
	if !ok {
		return Trigger{}, ErrNotFound
	}
	s.byID[id] = &t
	if err := s.flushLocked(); err != nil {
		s.byID[id] = prev
		return Trigger{}, err
	}
	s.rev.Add(1)
	return withProblem(t), nil
}

// Delete removes a trigger. usedBy names the automations still referencing it; a non-empty
// list refuses the delete rather than leaving them pointing at nothing.
func (s *Store) Delete(id string, usedBy []string) error {
	if len(usedBy) > 0 {
		return fmt.Errorf("%w: %v still reference it", ErrInUse, usedBy)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.byID, id)
	if err := s.flushLocked(); err != nil {
		s.byID[id] = prev
		return err
	}
	s.rev.Add(1)
	return nil
}

// flushLocked writes the whole file atomically. Synchronous on every mutation: the set is
// small, changes are operator-paced, and a trigger that was saved must be there after a
// crash — an automation silently reverting to an older filter is the failure this avoids.
func (s *Store) flushLocked() error {
	out := make([]*Trigger, 0, len(s.byID))
	for _, t := range s.byID {
		out = append(out, t)
	}
	// Sorted so the file is stable across saves and diffs cleanly; an operator may well
	// keep this under version control.
	slices.SortFunc(out, func(a, b *Trigger) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})

	data, err := json.MarshalIndent(file{Version: FileVersion, Triggers: out}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding triggers: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(s.path, append(data, '\n'), 0o600)
}
