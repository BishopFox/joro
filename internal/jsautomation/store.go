package jsautomation

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BishopFox/joro/internal/jsruntime"
)

// Installed automations live in ~/.joro/automations/<id>/ as three files:
//
//	joro.json         the manifest, author-owned
//	<entrypoint>.js   the source, a real file an operator can open in their own editor
//	joro.state.json   enabled / limits / triggers / revisions, operator-owned
//
// On disk rather than in a project config, because a project config is published to
// teammates: shipping executable code that runs against the full SDK bundle is exactly
// the privilege transfer that keeps automation tokens out of project configs too. The
// consequence is that automations are machine-global, which is also why "enabled" is.
//
// Three files rather than one, for two reasons. The source has to be a real .js file —
// a pentester will open it in their own editor, and a JSON-escaped source string is
// hostile to that. And operator state is separate from author state so installing an
// update never silently reverts a lowered limit or a trigger someone switched off.

var (
	ErrNotFound     = errors.New("no such automation")
	ErrExists       = errors.New("an automation with that id is already installed")
	ErrHashMismatch = errors.New("the automation changed since it was read")
)

const (
	manifestFile = "joro.json"
	stateFile    = "joro.state.json"
)

// Store reads and writes installed automation packages.
type Store struct {
	mu  sync.Mutex
	dir string
	// rev increments on every mutation so a consumer that caches the installed set —
	// the trigger dispatcher — can reload only when something actually changed rather
	// than re-reading every package on a 250ms tick.
	rev atomic.Uint64

	// MaxSourceBytes reports the operator's program-size limit at install time, where
	// the run's own copy of it is not in reach. A getter because the limit is edited at
	// runtime; nil takes the shipped default.
	MaxSourceBytes func() int
}

// NewStore returns a store rooted at dir, which is created lazily on first write.
func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) sourceLimit() int {
	if s.MaxSourceBytes == nil {
		return 0
	}
	return s.MaxSourceBytes()
}

// Revision reports the mutation counter.
func (s *Store) Revision() uint64 { return s.rev.Load() }

// path resolves an automation's directory, validating the id here rather than trusting
// that it was validated upstream.
//
// This is deliberate duplication. The plugin loader validates a name in one file and
// joins it into a path in another, which is safe today only because the order happens to
// hold; a store whose only defense against traversal lives in a different package is one
// refactor away from not having one.
func (s *Store) path(id string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(id))
	if clean == "" || len(clean) > MaxIDLen || !idPattern.MatchString(clean) {
		return "", fmt.Errorf("invalid automation id %q", id)
	}
	return filepath.Join(s.dir, clean), nil
}

// List loads every installed automation, newest-installed first.
//
// A package that fails to load is logged and skipped rather than failing the whole list,
// following the plugin loader: one corrupt manifest must not hide every other
// automation from the operator who needs to go fix it.
func (s *Store) List() []*Automation {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[automation] reading %s: %v", s.dir, err)
		}
		return nil
	}

	out := make([]*Automation, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		a, err := s.loadLocked(e.Name())
		if err != nil {
			log.Printf("[automation] skipping %q: %v", e.Name(), err)
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].State.InstalledAt.After(out[j].State.InstalledAt)
	})
	return out
}

// Load reads one automation, source included.
func (s *Store) Load(id string) (*Automation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(id)
}

func (s *Store) loadLocked(id string) (*Automation, error) {
	dir, err := s.path(id)
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading %s: %w", manifestFile, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", manifestFile, err)
	}
	m.Normalize()
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", manifestFile, err)
	}
	// The directory name is authoritative, the same rule readProjectMeta applies to a
	// sidecar: a hand-edited id inside the file must not point Joro at another package.
	if m.ID != strings.ToLower(strings.TrimSpace(id)) {
		return nil, fmt.Errorf("%s declares id %q but lives in %q", manifestFile, m.ID, id)
	}

	src, err := os.ReadFile(filepath.Join(dir, m.Entrypoint))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", m.Entrypoint, err)
	}

	st := State{}
	if b, err := os.ReadFile(filepath.Join(dir, stateFile)); err == nil {
		if err := json.Unmarshal(b, &st); err != nil {
			// A corrupt sidecar must not make the package unloadable, but it must not
			// silently read as "enabled" either: defaults are inert.
			log.Printf("[automation] %s: unreadable %s, using defaults: %v", id, stateFile, err)
			st = State{}
		}
	}

	return &Automation{
		Manifest:   m,
		State:      st,
		Source:     string(src),
		SourceHash: HashSource(string(src)),
	}, nil
}

// Install writes a new package. It refuses an id that already exists rather than
// overwriting: replacing installed code is Update's job, and Update has the
// hash precondition that makes a replacement deliberate.
func (s *Store) Install(m Manifest, source string) (*Automation, error) {
	m.Normalize()
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateSource(source, s.sourceLimit()); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := s.path(m.ID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dir); err == nil {
		return nil, ErrExists
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("checking %s: %w", dir, err)
	}

	now := time.Now().UTC()
	st := State{
		// Installed disabled. An operator reviews code, triggers and limits, and then
		// arms it; nothing an install can do should start something running.
		Enabled:     false,
		InstalledAt: now,
		UpdatedAt:   now,
		Revisions:   []Revision{{Hash: HashSource(source), At: now, Bytes: len(source)}},
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := s.writeAllLocked(dir, m, source, st); err != nil {
		// Leave nothing half-installed: a directory with a manifest and no source
		// would show up in List as a broken package forever.
		_ = os.RemoveAll(dir)
		return nil, err
	}

	s.rev.Add(1)
	return &Automation{Manifest: m, State: st, Source: source, SourceHash: HashSource(source)}, nil
}

// Update replaces an installed package's manifest and source.
//
// expectedHash is required while the automation is armed. Silently replacing code that
// something is actively triggering is how an operator ends up supervising an automation
// they have not read, so a concurrent edit has to lose rather than win.
func (s *Store) Update(id string, m Manifest, source, expectedHash string) (*Automation, error) {
	m.Normalize()
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateSource(source, s.sourceLimit()); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.loadLocked(id)
	if err != nil {
		return nil, err
	}
	if m.ID != cur.Manifest.ID {
		return nil, fmt.Errorf("cannot change an automation's id (%q -> %q); install a new one instead",
			cur.Manifest.ID, m.ID)
	}
	if cur.Runnable() {
		switch {
		case expectedHash == "":
			return nil, fmt.Errorf("%w: this automation is enabled, so an update must state the "+
				"source hash it is replacing (expectedHash)", ErrHashMismatch)
		case expectedHash != cur.SourceHash:
			return nil, ErrHashMismatch
		}
	}

	dir, err := s.path(id)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	st := cur.State
	st.UpdatedAt = now
	newHash := HashSource(source)
	if newHash != cur.SourceHash {
		st.Revisions = append(st.Revisions, Revision{Hash: newHash, At: now, Bytes: len(source)})
		if len(st.Revisions) > MaxRevisions {
			st.Revisions = st.Revisions[len(st.Revisions)-MaxRevisions:]
		}
	}
	// A trigger the operator switched off stays off; one the update newly declares is
	// not armed by that fact alone, because ArmedTriggers only reads the manifest for
	// triggers the operator has not overridden.
	if cur.Manifest.Entrypoint != m.Entrypoint {
		_ = os.Remove(filepath.Join(dir, cur.Manifest.Entrypoint))
	}
	if err := s.writeAllLocked(dir, m, source, st); err != nil {
		return nil, err
	}

	s.rev.Add(1)
	return &Automation{Manifest: m, State: st, Source: source, SourceHash: newHash}, nil
}

// SetState applies a mutation to the operator-owned sidecar and nothing else. The
// manifest and the source are not rewritten, which is what makes toggling a flag cheap
// and keeps an author's artifact byte-identical across an operator's decisions.
func (s *Store) SetState(id string, mutate func(*State)) (*Automation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.loadLocked(id)
	if err != nil {
		return nil, err
	}
	dir, err := s.path(id)
	if err != nil {
		return nil, err
	}

	st := cur.State
	mutate(&st)
	st.UpdatedAt = time.Now().UTC()
	if err := s.writeStateLocked(dir, st); err != nil {
		return nil, err
	}

	cur.State = st
	s.rev.Add(1)
	return cur, nil
}

// Delete removes a package and everything under it.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := s.path(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing %s: %w", dir, err)
	}
	s.rev.Add(1)
	return nil
}

func (s *Store) writeAllLocked(dir string, m Manifest, source string, st State) error {
	mjson, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding manifest: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, manifestFile), append(mjson, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, m.Entrypoint), []byte(source), 0o600); err != nil {
		return err
	}
	return s.writeStateLocked(dir, st)
}

func (s *Store) writeStateLocked(dir string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	return writeFileAtomic(filepath.Join(dir, stateFile), append(b, '\n'), 0o600)
}

// writeFileAtomic writes via a temp file and a rename, so an interrupted write leaves the
// previous content rather than a truncated file. configstore writes in place; the token
// store does it this way, and installed code deserves the same treatment — a half-written
// automation is a package that fails to load with no obvious cause.
//
// The temp file is created with os.CreateTemp, which opens O_EXCL under a name it
// generates. Two properties follow, and both are wanted: the open fails outright rather
// than writing through anything that already sits at that path, and the name is not
// predictable, so it cannot be staked out in advance. A fixed ".tmp" suffix has neither —
// it is guessable, and a plain write to it follows what it finds. The rename is safe
// either way, since it replaces a path rather than resolving through it.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating a temp file beside %s: %w", path, err)
	}
	tmp := f.Name()

	// Every failure past this point removes the temp file: a leftover would otherwise
	// accumulate in the automation's directory on each failed write.
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}

	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("writing %s: %w", tmp, err))
	}
	// CreateTemp opens at 0600; set the requested mode explicitly so the file on disk
	// does not depend on that staying true.
	if err := f.Chmod(perm); err != nil {
		return fail(fmt.Errorf("setting mode on %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming onto %s: %w", path, err)
	}
	return nil
}

// ValidateSource rejects a package whose source could never run: too large, or not
// parseable as JavaScript.
//
// Compiling at install time rather than at first run means a syntax error is reported to
// whoever submitted the package, while they are still looking at it, instead of surfacing
// hours later as a trigger that quietly fails. Compilation parses and does not execute.
func ValidateSource(source string, maxBytes int) error {
	if strings.TrimSpace(source) == "" {
		return errors.New("source is required")
	}
	return jsruntime.Validate(source, maxBytes)
}
