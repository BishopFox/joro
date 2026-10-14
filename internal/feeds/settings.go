package feeds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/BishopFox/joro/internal/atomicfile"
)

// Feed settings persist to ~/.joro/feeds.json (0600).
//
// Off by default, and a store of its own rather than a field on the session Settings or the
// project config, for the reason the MCP toggle is: enabling feeds starts outbound traffic
// from the operator's IP, so the choice must survive a restart and must not travel to a
// teammate inside a project file. The snapshot/cache itself is never persisted — it is
// re-fetched after a restart.

const (
	settingsFileVersion = 1
	// MinIntervalMinutes floors the refresh so Settings cannot drive NVD into its rate limit.
	MinIntervalMinutes     = 15
	DefaultIntervalMinutes = 15
)

// State is the operator's feed configuration.
type State struct {
	Enabled         bool              `json:"enabled"`
	Categories      map[Category]bool `json:"categories"`
	IntervalMinutes int               `json:"intervalMinutes"`
	// RouteThroughSocks sends feed egress through the operator's configured SOCKS proxy.
	// Off by default: feed traffic (NVD/CISA/ExploitDB/FIRST.org) is incidental intel, not
	// engagement traffic, so it should not consume or reveal the operator's tunnel unless
	// they ask. Honored only when a SOCKS proxy is actually configured.
	RouteThroughSocks bool `json:"routeThroughSocks"`
}

// DefaultState is feeds on, all categories armed, at the floor interval, direct egress.
func DefaultState() State {
	return State{
		Enabled: true,
		Categories: map[Category]bool{
			CategoryCVE:      true,
			CategoryKEV:      true,
			CategoryHeadline: true,
		},
		IntervalMinutes:   DefaultIntervalMinutes,
		RouteThroughSocks: false,
	}
}

func (st State) clone() State {
	cats := make(map[Category]bool, len(st.Categories))
	for k, v := range st.Categories {
		cats[k] = v
	}
	st.Categories = cats
	return st
}

// normalizeState clamps an incoming or on-disk state to a known shape: every category key
// present, the interval floored.
func normalizeState(st State) State {
	out := DefaultState()
	out.Enabled = st.Enabled
	out.RouteThroughSocks = st.RouteThroughSocks
	if st.Categories != nil {
		out.Categories = map[Category]bool{
			CategoryCVE:      st.Categories[CategoryCVE],
			CategoryKEV:      st.Categories[CategoryKEV],
			CategoryHeadline: st.Categories[CategoryHeadline],
		}
	}
	if st.IntervalMinutes >= MinIntervalMinutes {
		out.IntervalMinutes = st.IntervalMinutes
	}
	return out
}

type settingsFile struct {
	Version int   `json:"version"`
	State   State `json:"state"`
}

// SettingsStore reads and writes feeds.json.
type SettingsStore struct {
	mu    sync.RWMutex
	path  string
	state State
}

// NewSettingsStore opens feeds.json, creating nothing until the first write. A file that will
// not parse is a hard error rather than a silent default, the same discipline the webhook and
// trigger stores use.
func NewSettingsStore(dir string) (*SettingsStore, error) {
	s := &SettingsStore{
		path:  filepath.Join(dir, "feeds.json"),
		state: DefaultState(),
	}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.path, err)
	}
	var f settingsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	s.state = normalizeState(f.State)
	return s, nil
}

// Get returns a copy of the current state.
func (s *SettingsStore) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.clone()
}

// Set normalizes, stores, and persists a new state, returning the stored copy.
func (s *SettingsStore) Set(st State) (State, error) {
	st = normalizeState(st)
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.state
	s.state = st
	if err := s.flushLocked(); err != nil {
		s.state = prev
		return State{}, err
	}
	return s.state.clone(), nil
}

func (s *SettingsStore) flushLocked() error {
	data, err := json.MarshalIndent(settingsFile{Version: settingsFileVersion, State: s.state}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding feed settings: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(s.path, append(data, '\n'), 0o600)
}
