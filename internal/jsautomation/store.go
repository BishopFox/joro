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

	"github.com/BishopFox/joro/internal/atomicfile"
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
//
// # A command package has two files, not three
//
// KindCommand has no source file. Its body is the manifest's command block, and its
// Source is that block rendered — see sourceOf. The argument for a real .js file does
// not carry over: a spec is structured data a form edits, not text an author writes, so
// there is nothing for an editor to open and a second copy on disk beside the manifest
// would be a thing to drift.
//
// Everything downstream still works, because Source is what the record machinery is
// written against: the hash identifies the exact command, the revision list tracks
// changes to it, and the run log retains verbatim what ran. Which means editing an
// argument cuts a revision while editing a description does not — the description is not
// part of what runs, so it is not part of what is rendered.

var (
	ErrNotFound     = errors.New("no such automation")
	ErrExists       = errors.New("an automation with that id is already installed")
	ErrHashMismatch = errors.New("the automation changed since it was read")

	// ErrEnabled means a capability tried to replace code the operator has armed.
	// Enabling it is them agreeing to supervise that code, so replacing it underneath
	// them is not something a token gets to do.
	ErrEnabled = errors.New("this automation is enabled; the operator has to disable it " +
		"before its code can be replaced")

	// ErrTooManyPackages means MaxAgentPackages is reached.
	ErrTooManyPackages = errors.New("this Joro already holds the maximum number of " +
		"token-stored automations; the operator has to remove one first")

	// ErrCommandNotSubmittable means a capability tried to store a command package.
	// Only the operator installs those, from the UI. See InstallAs.
	ErrCommandNotSubmittable = errors.New("a command automation cannot be stored by an " +
		"automation token: it runs a local program, so only the operator installs one")

	// ErrKindChange means a write tried to turn a script into a command or back.
	// Refused for the same reason changing an id is: the body is not being edited, it
	// is being replaced by a different sort of thing, and the revision history would
	// read as one continuous artifact when it is two.
	ErrKindChange = errors.New("an automation's kind cannot be changed; install a new one instead")
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
	return s.listLocked()
}

func (s *Store) listLocked() []*Automation {
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

	var src string
	if m.IsCommand() {
		// Derived, not read: there is no source file, and the manifest already holds
		// everything that decides what runs.
		src = sourceOf(m, "")
	} else {
		b, rerr := os.ReadFile(filepath.Join(dir, m.Entrypoint))
		if rerr != nil {
			return nil, fmt.Errorf("reading %s: %w", m.Entrypoint, rerr)
		}
		src = string(b)
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
		Source:     src,
		SourceHash: HashSource(src),
	}, nil
}

// sourceOf returns the text that *is* this package's body.
//
// For a script that is what the caller supplied. For a command it is the rendered spec,
// and the caller's argument is ignored outright rather than merged or preferred: a
// command's body is decided by its manifest, so accepting a source alongside one would
// let a write store a hash of text that has nothing to do with what would run.
//
// Every write path routes through this before hashing, so the invariant holds at one
// place instead of at four.
func sourceOf(m Manifest, source string) string {
	if !m.IsCommand() || m.Command == nil {
		return source
	}
	return m.Command.Render()
}

// Install writes a new package. It refuses an id that already exists rather than
// overwriting: replacing installed code is Update's job, and Update has the
// hash precondition that makes a replacement deliberate.
func (s *Store) Install(m Manifest, source string) (*Automation, error) {
	return s.InstallAs(m, source, "")
}

// InstallAs is Install, recording which automation token submitted the code and refusing
// once MaxAgentPackages token-stored packages exist. Install delegates here with an empty
// author, which is what the operator's own path means.
//
// The ceiling applies only to token-stored packages, and counts them wherever they sit:
// enabling one does not make room, because the point of the limit is a reviewable list,
// not a quota on disk.
func (s *Store) InstallAs(m Manifest, source, author string) (*Automation, error) {
	source, err := s.validateWrite(&m, source)
	if err != nil {
		return nil, err
	}
	// A capability may not store a command package, and this is the third of the three
	// places that holds. The other two are structural — Manifest.Normalize reads an
	// absent kind as a script, and the install capability's argument struct has no kind
	// field at all — so an agent has no way to ask for one. This catches the case where
	// a later argument or a hand-built Manifest gives it one anyway.
	//
	// The reason is that a command package's authority is not a grant. A script is
	// bounded by the SDK bundle whatever it contains; a command is bounded by nothing
	// Joro evaluates, so the only thing standing between submitted code and local
	// execution is a person having read it. An operator can be that person for code
	// they wrote. They cannot be for a directory an agent fills.
	if author != "" && m.IsCommand() {
		return nil, ErrCommandNotSubmittable
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
	if author != "" && s.countAuthoredLocked() >= MaxAgentPackages {
		return nil, ErrTooManyPackages
	}

	now := time.Now().UTC()
	st := State{
		// Installed disabled. An operator reviews code, triggers and limits, and then
		// arms it; nothing an install can do should start something running.
		Enabled:     false,
		Author:      author,
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
	return s.UpdateAs(id, m, source, expectedHash, "")
}

// UpdateAs is Update, recording the author. The operator's own path passes an empty one,
// which clears the field — the right reading: they have read the code and rewritten it as
// their own.
func (s *Store) UpdateAs(id string, m Manifest, source, expectedHash, author string) (*Automation, error) {
	source, err := s.validateWrite(&m, source)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLocked(id, m, source, expectedHash, author, false)
}

// ReplaceDisabled overwrites an installed package the operator has not enabled, whoever
// wrote it.
//
// The enabled test happens here, under the store's own lock. A capability that loaded the
// package, saw it disabled and then called Update would leave a window in which the
// operator arms it and the write still lands anyway.
//
// expectedHash is required unconditionally, unlike Update, which demands one only while
// the package is armed. It is a staleness guard rather than a permission — Summarize
// reports every package's hash, so a caller can always obtain one — but it does mean a
// blind overwrite costs a prior read.
func (s *Store) ReplaceDisabled(id string, m Manifest, source, expectedHash, author string) (*Automation, error) {
	source, err := s.validateWrite(&m, source)
	if err != nil {
		return nil, err
	}
	if m.IsCommand() {
		// The same rule InstallAs states: only the operator installs a command
		// package, so only the operator replaces one. Checked here as well as there
		// because this is a separate grant — storing something new and rewriting
		// something that is already there are different acts, and a token can hold
		// script.replace without script.install.
		return nil, ErrCommandNotSubmittable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLocked(id, m, source, expectedHash, author, true)
}

// validateWrite normalizes and checks what every write path checks, outside the lock —
// manifest shape, and a body that is valid for its kind — and returns the body to store.
//
// It returns the source rather than taking a pointer to it because a command's body is
// derived from the manifest: a caller cannot know it before Normalize has run, so having
// this hand back the answer is what stops each write path deriving it again slightly
// differently.
func (s *Store) validateWrite(m *Manifest, source string) (string, error) {
	m.Normalize()
	if err := m.Validate(); err != nil {
		return "", err
	}
	body := sourceOf(*m, source)

	if m.IsCommand() {
		// Manifest.Validate already ran Spec.Validate, which is the command's
		// equivalent of compiling: it resolves the executable and refuses a
		// placeholder nothing supplies. Only the size check is left, and it applies
		// for the same reason it does to a script — the API request that carries a
		// package is bounded, so what is stored has to fit in one.
		if limit := s.sourceLimit(); limit > 0 && len(body) > limit {
			return "", fmt.Errorf("the rendered command is %d bytes, over the %d limit", len(body), limit)
		}
		return body, nil
	}
	return body, ValidateSource(body, s.sourceLimit())
}

// countAuthoredLocked counts packages a capability stored. See MaxAgentPackages.
func (s *Store) countAuthoredLocked() int {
	n := 0
	for _, a := range s.listLocked() {
		if a.State.Author != "" {
			n++
		}
	}
	return n
}

// updateLocked is the shared body of every replacement. requireDisabled adds the rule that
// separates a capability's write from the operator's: they may replace armed code, having
// stated the hash; a token may not, at all.
func (s *Store) updateLocked(id string, m Manifest, source, expectedHash, author string,
	requireDisabled bool) (*Automation, error) {
	cur, err := s.loadLocked(id)
	if err != nil {
		return nil, err
	}
	if m.ID != cur.Manifest.ID {
		return nil, fmt.Errorf("cannot change an automation's id (%q -> %q); install a new one instead",
			cur.Manifest.ID, m.ID)
	}
	if m.Kind != cur.Manifest.Kind {
		return nil, fmt.Errorf("%w (%q -> %q)", ErrKindChange, cur.Manifest.Kind, m.Kind)
	}
	switch {
	case requireDisabled:
		// Paused counts as armed: it is something the breaker stopped and the operator
		// has not answered about yet, so their Enabled flag still records their intent.
		if cur.State.Enabled || cur.State.Paused {
			return nil, ErrEnabled
		}
		// The sentinel goes last here, unlike the operator's branch below: this message
		// leads with what to supply, and "the automation changed since it was read" is
		// not what happened when nothing was stated at all.
		if expectedHash == "" {
			return nil, fmt.Errorf("expectedHash is required: state the source hash the "+
				"automation has now, so this cannot overwrite a revision that was never "+
				"read (%w)", ErrHashMismatch)
		}
		if expectedHash != cur.SourceHash {
			return nil, ErrHashMismatch
		}
	case cur.Runnable():
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
	st.Author = author
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
	//
	// Nothing has to be carried across for the trigger itself: a manifest holds only a
	// reference, and the definition it names lives in the trigger store, untouched by any
	// write here.

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
	if err := atomicfile.Write(filepath.Join(dir, manifestFile), append(mjson, '\n'), 0o600); err != nil {
		return err
	}
	// A command has no source file: source is a rendering of the manifest that was just
	// written, so a second copy on disk would be the same fact twice with nothing
	// keeping them in step.
	if !m.IsCommand() {
		if err := atomicfile.Write(filepath.Join(dir, m.Entrypoint), []byte(source), 0o600); err != nil {
			return err
		}
	}
	return s.writeStateLocked(dir, st)
}

func (s *Store) writeStateLocked(dir string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	return atomicfile.Write(filepath.Join(dir, stateFile), append(b, '\n'), 0o600)
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
