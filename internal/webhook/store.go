package webhook

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
	"github.com/BishopFox/joro/internal/trigger"
)

// The webhook store: one file, ~/.joro/webhooks.json, 0600.
//
// Global rather than per-project, and forced by the same argument internal/trigger's store
// records: a webhook references a trigger by id, and the triggers are global because the
// automations referencing them are. A per-project webhook would resolve on one engagement and
// dangle on the next. It also holds secrets — a bearer token, a signing key, a Slack URL that
// is itself the credential — which is a second reason it must not travel inside a project file
// published to teammates.

// FileVersion is the on-disk schema version. Bump it only alongside a migration; there is no
// backfill machinery here for the reason triggers.json has none — a definition an operator
// relies on must not inherit "helpfully add the new default" semantics.
const FileVersion = 1

// MaxWebhooks bounds the file. Smaller than MaxTriggers because each one holds a compiled
// filter set and a delivery queue, and because a hundred notification endpoints is not a
// configuration anyone meant.
const MaxWebhooks = 50

var (
	// ErrNotFound means no webhook has that id.
	ErrNotFound = errors.New("no such webhook")
	// ErrExists means one already does.
	ErrExists = errors.New("a webhook with that id already exists")
)

// TriggerResolver resolves a reference to its definition. Satisfied by *trigger.Store, and
// nil-tolerated: without one only the built-in events exist, which is a Joro that has never
// had a custom trigger rather than an error.
type TriggerResolver interface {
	Resolve(ref string) (trigger.Trigger, error)
	Revision() uint64
}

type file struct {
	Version  int        `json:"version"`
	Webhooks []*Webhook `json:"webhooks"`
}

// Store holds the operator's webhooks.
type Store struct {
	mu   sync.RWMutex
	path string
	byID map[string]*Webhook

	// rev increments on every mutation so the dispatcher recompiles only when something
	// actually changed. The same idiom trigger.Store, jsautomation.Store and detect.Store
	// all use.
	rev atomic.Uint64

	triggers TriggerResolver
}

// NewStore opens the webhook file, creating nothing until the first write.
//
// A file that will not parse is a hard error rather than a silent empty set, for the reason
// trigger.NewStore gives: the two look nothing alike from the operator's side. An empty store
// is a Joro that quietly stopped notifying anyone; a loud failure says why.
func NewStore(dir string, triggers TriggerResolver) (*Store, error) {
	s := &Store{
		path:     filepath.Join(dir, "webhooks.json"),
		byID:     map[string]*Webhook{},
		triggers: triggers,
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
	for _, w := range f.Webhooks {
		if w == nil || w.ID == "" {
			continue
		}
		w.Normalize()
		// Deliberately not validated here, the same way a trigger is not. A webhook this
		// build cannot read still has to list so the operator can see it and fix it;
		// Problem says why it will not deliver, and the dispatcher refuses to arm it.
		s.byID[w.ID] = w
	}
	return s, nil
}

// Revision reports the mutation counter.
func (s *Store) Revision() uint64 { return s.rev.Load() }

// List returns every webhook, sorted by name, each with Problem filled in.
func (s *Store) List() []Webhook {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Webhook, 0, len(s.byID))
	for _, w := range s.byID {
		out = append(out, s.withProblemLocked(*w))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one webhook, secrets included. Callers serving the API must strip them; see
// handlers_webhooks.go.
func (s *Store) Get(id string) (Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.byID[id]
	if !ok {
		return Webhook{}, ErrNotFound
	}
	return s.withProblemLocked(*w), nil
}

// UsedBy names the webhooks referencing a trigger, so deleting one that is still in use is
// refused rather than leaving a webhook silently poisoned.
func (s *Store) UsedBy(triggerID string) []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []string
	for _, w := range s.byID {
		if slices.Contains(w.Triggers, triggerID) {
			out = append(out, w.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Create stores a new webhook.
func (s *Store) Create(w Webhook) (Webhook, error) {
	if err := s.prepare(&w); err != nil {
		return Webhook{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.byID[w.ID]; dup {
		return Webhook{}, ErrExists
	}
	if len(s.byID) >= MaxWebhooks {
		return Webhook{}, fmt.Errorf("this Joro holds %d webhooks, which is the limit", MaxWebhooks)
	}
	s.byID[w.ID] = &w
	if err := s.flushLocked(); err != nil {
		delete(s.byID, w.ID)
		return Webhook{}, err
	}
	s.rev.Add(1)
	return s.withProblemLocked(w), nil
}

// Update replaces a stored webhook. The id is frozen, as a trigger's and an automation's are.
//
// A secret the caller left empty keeps what is stored, so the API can withhold secrets on the
// way out without a round trip silently clearing them. An operator clearing one on purpose
// changes the auth kind or turns signing off, both of which are visible acts.
func (s *Store) Update(id string, w Webhook) (Webhook, error) {
	// Held across the read, the validation and the write. prepare touches no state of this
	// store — eventsFor resolves against the trigger store, and ParseTemplate is pure — so
	// there is nothing to gain by releasing it, and releasing would let the breaker's pause
	// land between reading the stored secrets and writing them back, where this would
	// silently undo it.
	s.mu.Lock()
	defer s.mu.Unlock()

	prev, ok := s.byID[id]
	if !ok {
		return Webhook{}, ErrNotFound
	}
	carryForwardSecrets(&w, prev)

	w.ID = id
	if err := s.prepare(&w); err != nil {
		return Webhook{}, err
	}
	s.byID[id] = &w
	if err := s.flushLocked(); err != nil {
		s.byID[id] = prev
		return Webhook{}, err
	}
	s.rev.Add(1)
	return s.withProblemLocked(w), nil
}

// Delete removes a webhook.
func (s *Store) Delete(id string) error {
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

// SetState changes what Joro decided about a webhook rather than what the operator did — the
// breaker pausing one. Enabled is left alone so resuming restores the operator's intent.
func (s *Store) SetState(id string, fn func(*Webhook)) (Webhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.byID[id]
	if !ok {
		return Webhook{}, ErrNotFound
	}
	next := *w
	fn(&next)
	s.byID[id] = &next
	if err := s.flushLocked(); err != nil {
		s.byID[id] = w
		return Webhook{}, err
	}
	s.rev.Add(1)
	return s.withProblemLocked(next), nil
}

// prepare normalizes, validates, and checks the template against the events this webhook's
// triggers resolve to.
func (s *Store) prepare(w *Webhook) error {
	w.Normalize()
	w.Problem = ""
	if err := w.Validate(); err != nil {
		return err
	}
	events, err := s.eventsFor(w.Triggers)
	if err != nil {
		return err
	}
	return w.ValidateTemplate(events)
}

// eventsFor resolves a webhook's trigger references to the events they watch.
//
// A reference that resolves to nothing is refused on the write path — unlike an automation's,
// which is checked only when it is armed. The difference is that a webhook is authored in one
// screen alongside its triggers, so the operator is standing there and can be told; a manifest
// is loaded from disk, where refusing would make the package vanish instead of reporting.
func (s *Store) eventsFor(refs []string) ([]string, error) {
	var out []string
	for _, ref := range refs {
		def, err := s.resolve(ref)
		if err != nil {
			return nil, fmt.Errorf("trigger %q does not exist", ref)
		}
		if !trigger.Dispatched(def.On) {
			return nil, fmt.Errorf("trigger %q watches %q, which is started by hand and never "+
				"arrives on its own", ref, def.On)
		}
		if !slices.Contains(out, def.On) {
			out = append(out, def.On)
		}
	}
	return out, nil
}

func (s *Store) resolve(ref string) (trigger.Trigger, error) {
	if s.triggers != nil {
		return s.triggers.Resolve(ref)
	}
	if !trigger.IsBuiltin(ref) {
		return trigger.Trigger{}, trigger.ErrNotFound
	}
	for _, t := range trigger.BuiltinTriggers() {
		if t.ID == ref {
			return t, nil
		}
	}
	return trigger.Trigger{}, trigger.ErrNotFound
}

// TriggerRevision reports the trigger store's counter, so the dispatcher recompiles when a
// trigger changes without the webhook itself being touched.
func (s *Store) TriggerRevision() uint64 {
	if s == nil || s.triggers == nil {
		return 0
	}
	return s.triggers.Revision()
}

// withProblemLocked fills in why a stored webhook will not deliver, leaving Problem empty when
// it will. Computed on the way out rather than stored, so it can never disagree with what the
// dispatcher actually does. Called with s.mu held.
func (s *Store) withProblemLocked(w Webhook) Webhook {
	if err := w.Validate(); err != nil {
		w.Problem = err.Error()
		return w
	}
	events, err := s.eventsFor(w.Triggers)
	if err != nil {
		w.Problem = err.Error()
		return w
	}
	if err := w.ValidateTemplate(events); err != nil {
		w.Problem = err.Error()
		return w
	}
	for _, ref := range w.Triggers {
		def, err := s.resolve(ref)
		if err != nil {
			continue
		}
		if c := trigger.Compile(&def); c.Poisoned {
			w.Problem = fmt.Sprintf("trigger %q will not fire: %s", ref, c.Reason)
			return w
		}
	}
	return w
}

// carryForwardSecrets keeps a stored secret the caller did not resend. The API returns "" for
// every secret, so a plain round trip would otherwise wipe them all.
func carryForwardSecrets(next *Webhook, prev *Webhook) {
	if next.Auth.Token == "" && next.Auth.Kind == prev.Auth.Kind {
		next.Auth.Token = prev.Auth.Token
	}
	if next.Signing.Secret == "" && prev.Signing.Enabled {
		next.Signing.Secret = prev.Signing.Secret
	}
	byName := make(map[string]string, len(prev.Headers))
	for _, h := range prev.Headers {
		byName[h.Name] = h.Value
	}
	for i, h := range next.Headers {
		if h.Value == "" {
			next.Headers[i].Value = byName[h.Name]
		}
	}
}

// flushLocked writes the whole file atomically, at 0600 because it holds secrets. Synchronous
// on every mutation: the set is small, changes are operator-paced, and a webhook that was
// saved must be there after a crash.
func (s *Store) flushLocked() error {
	out := make([]*Webhook, 0, len(s.byID))
	for _, w := range s.byID {
		clean := *w
		clean.Problem = ""
		out = append(out, &clean)
	}
	// Sorted so the file is stable across saves and diffs cleanly.
	slices.SortFunc(out, func(a, b *Webhook) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})

	data, err := json.MarshalIndent(file{Version: FileVersion, Webhooks: out}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding webhooks: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(s.path, append(data, '\n'), 0o600)
}
