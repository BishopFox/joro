package techfp

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Tech is one technology observed on a host, folded over every response that
// contributed to it.
type Tech struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Confidence int      `json:"confidence"`
}

// HostTech is the technology set for one host.
type HostTech struct {
	Host         string    `json:"host"`
	Technologies []Tech    `json:"technologies"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// Store is the cumulative per-host technology map. It is rebuilt from the capture
// store on demand (a reset clears it), not persisted separately — the same reason
// echo's reflection map is in-memory: it is derivable from captured traffic.
type Store struct {
	mu    sync.RWMutex
	hosts map[string]map[string]*Tech
	seen  map[string]int // host -> count of HTML responses deep-scanned
	times map[string]time.Time
}

// NewStore creates an empty store.
func NewStore() *Store {
	return &Store{
		hosts: map[string]map[string]*Tech{},
		seen:  map[string]int{},
		times: map[string]time.Time{},
	}
}

// maxDeepScansPerHost caps how many HTML pages of one host get the expensive
// body/scriptSrc/meta pass. Technology is host-stable, so a handful of pages
// settles the set; further pages only re-confirm it.
const maxDeepScansPerHost = 8

// NeedsDeepScan reports whether this host still warrants the body-matching pass.
func (s *Store) NeedsDeepScan(host string) bool {
	host = normHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seen[host] < maxDeepScansPerHost
}

func (s *Store) noteDeepScan(host string) {
	s.seen[host]++
}

// Observe folds a response's detections into a host's set and reports whether
// anything changed (a new technology or a newly-learned version), which is what
// gates a broadcast.
func (s *Store) Observe(host string, deep bool, dets []Detection) bool {
	host = normHost(host)
	s.mu.Lock()
	defer s.mu.Unlock()
	if deep {
		s.noteDeepScan(host)
	}
	set := s.hosts[host]
	if set == nil {
		set = map[string]*Tech{}
		s.hosts[host] = set
	}
	changed := false
	for _, d := range dets {
		cur := set[d.Name]
		if cur == nil {
			set[d.Name] = &Tech{
				Name: d.Name, Version: d.Version,
				Categories: d.Categories, Confidence: d.Confidence,
			}
			changed = true
			continue
		}
		if d.Version != "" && cur.Version == "" {
			cur.Version = d.Version
			changed = true
		}
		if d.Confidence > cur.Confidence {
			cur.Confidence = d.Confidence
		}
	}
	if changed {
		s.times[host] = time.Now()
	}
	return changed
}

// Host returns the technology set for one host.
func (s *Store) Host(host string) (HostTech, bool) {
	host = normHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	set, ok := s.hosts[host]
	if !ok || len(set) == 0 {
		return HostTech{}, false
	}
	return s.snapshot(host, set), true
}

// Names returns just the detected technology names for a host, for scan gating.
func (s *Store) Names(host string) []string {
	host = normHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := s.hosts[host]
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	return out
}

// Hosts returns every host's technology set, newest first.
func (s *Store) Hosts() []HostTech {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]HostTech, 0, len(s.hosts))
	for host, set := range s.hosts {
		if len(set) == 0 {
			continue
		}
		out = append(out, s.snapshot(host, set))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

// Clear drops everything, for a cursor reset (history load/clear rewrites the
// sequence numbering the scanner walks).
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts = map[string]map[string]*Tech{}
	s.seen = map[string]int{}
	s.times = map[string]time.Time{}
}

// Summary counts hosts and distinct technologies.
func (s *Store) Summary() (hosts, techs int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	distinct := map[string]struct{}{}
	for _, set := range s.hosts {
		if len(set) == 0 {
			continue
		}
		hosts++
		for name := range set {
			distinct[name] = struct{}{}
		}
	}
	return hosts, len(distinct)
}

// snapshot builds a sorted HostTech. Caller holds the lock.
func (s *Store) snapshot(host string, set map[string]*Tech) HostTech {
	techs := make([]Tech, 0, len(set))
	for _, t := range set {
		techs = append(techs, *t)
	}
	sort.Slice(techs, func(i, j int) bool {
		if techs[i].Confidence != techs[j].Confidence {
			return techs[i].Confidence > techs[j].Confidence
		}
		return techs[i].Name < techs[j].Name
	})
	return HostTech{Host: host, Technologies: techs, UpdatedAt: s.times[host]}
}

func normHost(h string) string { return strings.ToLower(strings.TrimSpace(h)) }
