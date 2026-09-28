package echo

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultMaxReports bounds the per-message reports held for the request pane.
// The aggregate below is what survives; a report is the detail behind one row.
const defaultMaxReports = 2000

// maxEntryExamples bounds the reflections kept on an aggregate row.
const maxEntryExamples = 20

// SinkSummary is one distinct place a parameter lands, counted across every
// message that carried it.
type SinkSummary struct {
	Context   Context   `json:"context"`
	JSContext JSContext `json:"jsContext,omitempty"`
	Transform Transform `json:"transform"`
	Attr      string    `json:"attr,omitempty"`
	Count     int       `json:"count"`
	Breakout  bool      `json:"breakout"`
}

// Entry is one row of the map: a parameter on a host, and everywhere its values
// have been seen to come back.
type Entry struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Source Source `json:"source"`
	Name   string `json:"name"`

	Observations   int `json:"observations"`
	DistinctValues int `json:"distinctValues"`
	Reflections    int `json:"reflections"`
	Breakouts      int `json:"breakouts"`

	Sinks []SinkSummary `json:"sinks"`

	LastSeen         time.Time `json:"lastSeen"`
	ExampleRequestID string    `json:"exampleRequestId"`
	ExampleURL       string    `json:"exampleUrl"`
	ExampleValue     string    `json:"exampleValue"`

	// Examples are the most recent reflections for this parameter, for the
	// detail pane.
	Examples []Reflection `json:"examples,omitempty"`

	values map[string]struct{}
	// sinks maps a sink key to its index in Sinks.
	sinks map[string]int
}

// EntryID is the stable identity of a parameter on a host. Callers use it as an
// opaque handle; it is also the group dimension a finding is keyed on, so it
// must not change shape.
func EntryID(host string, src Source, name string) string {
	sum := sha256.Sum256([]byte(host + "\x00" + string(src) + "\x00" + name))
	return hex.EncodeToString(sum[:])[:16]
}

// Store holds the per-message reports and the aggregate map built from them.
//
// The aggregate is cumulative: evicting a report to stay within the ring does
// not decrement the row it contributed to. A map that shrank as history rolled
// over would report that a parameter stopped being reflected when all that
// happened is that the evidence scrolled off.
type Store struct {
	mu         sync.RWMutex
	reports    map[string]*Report
	order      []string
	maxReports int
	entries    map[string]*Entry

	revision atomic.Uint64
	scanned  atomic.Int64
}

func NewStore(maxReports int) *Store {
	if maxReports <= 0 {
		maxReports = defaultMaxReports
	}
	return &Store{
		reports:    map[string]*Report{},
		maxReports: maxReports,
		entries:    map[string]*Entry{},
	}
}

func (s *Store) Revision() uint64 { return s.revision.Load() }
func (s *Store) NoteScanned(n int) {
	if n > 0 {
		s.scanned.Add(int64(n))
	}
}

// Add files a report and folds it into the aggregate. A report with no
// reflections is still counted, because "this parameter is never reflected" is
// an answer.
func (s *Store) Add(rep *Report) {
	if rep == nil || rep.RequestID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.reports[rep.RequestID]; !exists {
		s.order = append(s.order, rep.RequestID)
	}
	s.reports[rep.RequestID] = rep
	for len(s.order) > s.maxReports {
		delete(s.reports, s.order[0])
		s.order = s.order[1:]
	}

	byParam := map[string][]Reflection{}
	for _, rf := range rep.Reflections {
		byParam[EntryID(rep.Host, rf.Source, rf.Name)] = append(
			byParam[EntryID(rep.Host, rf.Source, rf.Name)], rf)
	}
	for id, rfs := range byParam {
		e := s.entries[id]
		if e == nil {
			e = &Entry{
				ID: id, Host: rep.Host, Source: rfs[0].Source, Name: rfs[0].Name,
				values: map[string]struct{}{}, sinks: map[string]int{},
			}
			s.entries[id] = e
		}
		e.Observations++
		e.Reflections += len(rfs)
		e.LastSeen = rep.Timestamp
		e.ExampleRequestID = rep.RequestID
		e.ExampleURL = rep.URL
		e.ExampleValue = rfs[0].Value
		for _, rf := range rfs {
			e.values[rf.Value] = struct{}{}
			if rf.Breakout {
				e.Breakouts++
			}
			key := rf.SinkKey() + "|" + rf.Attr
			i, ok := e.sinks[key]
			if !ok {
				e.Sinks = append(e.Sinks, SinkSummary{
					Context: rf.Context, JSContext: rf.JSContext,
					Transform: rf.Transform, Attr: rf.Attr,
				})
				i = len(e.Sinks) - 1
				e.sinks[key] = i
			}
			e.Sinks[i].Count++
			if rf.Breakout {
				e.Sinks[i].Breakout = true
			}
		}
		e.DistinctValues = len(e.values)
		e.Examples = append(rfs, e.Examples...)
		if len(e.Examples) > maxEntryExamples {
			e.Examples = e.Examples[:maxEntryExamples]
		}
	}
	s.revision.Add(1)
}

// Report returns one message's analysis.
func (s *Store) Report(requestID string) (*Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reports[requestID]
	return r, ok
}

// Entry returns one aggregate row.
func (s *Store) Entry(id string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[id]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Filter narrows the map. Empty fields mean no constraint, so an unset filter
// returns everything.
type Filter struct {
	Host         string
	Sources      []string
	Contexts     []string
	Transforms   []string
	BreakoutOnly bool
	Search       string
	Sort         string
	Dir          string
	Offset       int
	Limit        int
}

// List returns the map rows matching f, plus the total before paging.
func (s *Store) List(f Filter) ([]Entry, int) {
	s.mu.RLock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if matches(e, f) {
			c := *e
			c.Examples = nil
			out = append(out, c)
		}
	}
	s.mu.RUnlock()

	sortEntries(out, f.Sort, f.Dir)
	total := len(out)
	if f.Offset > 0 {
		if f.Offset >= len(out) {
			return nil, total
		}
		out = out[f.Offset:]
	}
	if f.Limit > 0 && f.Limit < len(out) {
		out = out[:f.Limit]
	}
	return out, total
}

func matches(e *Entry, f Filter) bool {
	if f.BreakoutOnly && e.Breakouts == 0 {
		return false
	}
	if f.Host != "" && !strings.Contains(strings.ToLower(e.Host), strings.ToLower(f.Host)) {
		return false
	}
	if len(f.Sources) > 0 && !contains(f.Sources, string(e.Source)) {
		return false
	}
	if f.Search != "" {
		q := strings.ToLower(f.Search)
		if !strings.Contains(strings.ToLower(e.Name), q) &&
			!strings.Contains(strings.ToLower(e.ExampleValue), q) {
			return false
		}
	}
	if len(f.Contexts) > 0 && !anySink(e, func(s SinkSummary) bool {
		return contains(f.Contexts, string(s.Context))
	}) {
		return false
	}
	if len(f.Transforms) > 0 && !anySink(e, func(s SinkSummary) bool {
		return contains(f.Transforms, string(s.Transform))
	}) {
		return false
	}
	return true
}

func anySink(e *Entry, fn func(SinkSummary) bool) bool {
	for _, s := range e.Sinks {
		if fn(s) {
			return true
		}
	}
	return false
}

func contains(hay []string, v string) bool {
	for _, h := range hay {
		if h == v {
			return true
		}
	}
	return false
}

// sortEntries orders the map. The default puts what an operator should look at
// first: parameters that broke out, then the most reflected.
func sortEntries(es []Entry, col, dir string) {
	less := func(a, b Entry) bool {
		switch col {
		case "host":
			return a.Host < b.Host
		case "name":
			return a.Name < b.Name
		case "reflections":
			return a.Reflections > b.Reflections
		case "lastseen":
			return a.LastSeen.After(b.LastSeen)
		default:
			if (a.Breakouts > 0) != (b.Breakouts > 0) {
				return a.Breakouts > 0
			}
			if a.Reflections != b.Reflections {
				return a.Reflections > b.Reflections
			}
			return a.LastSeen.After(b.LastSeen)
		}
	}
	sort.SliceStable(es, func(i, j int) bool {
		if dir == "asc" {
			return less(es[j], es[i])
		}
		return less(es[i], es[j])
	})
}

// Summary is the aggregate shown on the tab header and pushed over the socket.
type Summary struct {
	Params      int            `json:"params"`
	Hosts       int            `json:"hosts"`
	Reflections int            `json:"reflections"`
	Breakouts   int            `json:"breakouts"`
	Scanned     int64          `json:"scanned"`
	ByContext   map[string]int `json:"byContext"`
	ByTransform map[string]int `json:"byTransform"`
}

func (s *Store) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := Summary{
		Scanned:     s.scanned.Load(),
		ByContext:   map[string]int{},
		ByTransform: map[string]int{},
	}
	hosts := map[string]struct{}{}
	for _, e := range s.entries {
		sum.Params++
		sum.Reflections += e.Reflections
		sum.Breakouts += e.Breakouts
		hosts[e.Host] = struct{}{}
		for _, sk := range e.Sinks {
			sum.ByContext[string(sk.Context)] += sk.Count
			sum.ByTransform[string(sk.Transform)] += sk.Count
		}
	}
	sum.Hosts = len(hosts)
	return sum
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Breakouts returns every row with a reflection that can leave its context, for
// the finding reconciliation.
func (s *Store) Breakouts() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Entry
	for _, e := range s.entries {
		if e.Breakouts > 0 {
			c := *e
			c.Examples = append([]Reflection(nil), e.Examples...)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = map[string]*Report{}
	s.order = nil
	s.entries = map[string]*Entry{}
	s.scanned.Store(0)
	s.revision.Add(1)
}

// Hosts lists every host with a row, for the filter bar.
func (s *Store) Hosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]struct{}{}
	for _, e := range s.entries {
		seen[e.Host] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
