package detect

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultMaxFindings bounds the in-memory store as a runaway guard.
const defaultMaxFindings = 20000

// FindingFilter holds the criteria for listing findings.
type FindingFilter struct {
	Severities  []string
	MinSeverity string
	Categories  []string
	RuleID      string
	Host        string
	Search      string
	Confidence  string
	// FP selects false-positive handling: "false" (default) hides them, "true"
	// shows only them, "all" shows everything.
	FP string
	// IncludeDisabled includes findings whose rule is currently switched off.
	// Disabling a rule retains its findings; this toggle controls visibility.
	IncludeDisabled bool
	Sort            string // "severity" (default) | "lastSeen" | "firstSeen" | "count"
	Dir             string // "desc" (default) | "asc"
	Offset          int
	Limit           int
}

// Store holds deduplicated findings. Every finding, from live scanning or from a
// rescan, enters through Upsert and is keyed on the engine's deterministic
// Finding.ID, so rescanning the same traffic merges rather than duplicates.
type Store struct {
	mu       sync.RWMutex
	byID     map[string]*Finding
	order    []string
	maxItems int

	// revision increments on every mutation, including ones that change no counts
	// (a false-positive toggle, a note edit). The auto-save fingerprint reads it.
	revision atomic.Uint64

	// generation is the current scan pass, used by an optional purge to drop
	// findings a rescan did not re-confirm.
	generation atomic.Uint64

	skippedEncoded atomic.Int64
	skippedBinary  atomic.Int64
	scanned        atomic.Int64
}

// NewStore returns an empty findings store. maxItems <= 0 uses the default.
func NewStore(maxItems int) *Store {
	if maxItems <= 0 {
		maxItems = defaultMaxFindings
	}
	return &Store{
		byID:     map[string]*Finding{},
		maxItems: maxItems,
	}
}

// Revision returns the mutation counter.
func (s *Store) Revision() uint64 { return s.revision.Load() }

// Generation returns the current scan generation.
func (s *Store) Generation() uint64 { return s.generation.Load() }

// NextGeneration advances the scan generation and returns the new value.
func (s *Store) NextGeneration() uint64 { return s.generation.Add(1) }

// NoteSkipped records a message the scanner could not read.
func (s *Store) NoteSkipped(reason string) {
	switch {
	case strings.HasPrefix(reason, "encoding:"):
		s.skippedEncoded.Add(1)
	case reason == "binary":
		s.skippedBinary.Add(1)
	}
}

// NoteScanned records that a message was scanned.
func (s *Store) NoteScanned(n int) { s.scanned.Add(int64(n)) }

// occKey identifies one sighting for counting purposes.
func occKey(o Occurrence) string {
	return o.RequestID + ":" + o.Part + ":" + itoa(o.Offset)
}

// itoa avoids importing strconv for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Upsert merges a finding into the store, returning the stored finding and
// whether it was newly created.
//
// On a hit it bumps LastSeen, appends the occurrence, and increments Count only
// for an occurrence not already in occSeen, which keeps a rescan idempotent.
// Operator state (false-positive mark, notes, severity override) is preserved.
func (s *Store) Upsert(f Finding) (*Finding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	gen := s.generation.Load()
	existing, ok := s.byID[f.ID]
	if !ok {
		nf := f
		nf.generation = gen
		nf.occSeen = map[string]struct{}{}
		for _, o := range nf.Occurrences {
			nf.occSeen[occKey(o)] = struct{}{}
		}
		if nf.Count == 0 {
			nf.Count = 1
		}
		s.byID[nf.ID] = &nf
		s.order = append(s.order, nf.ID)
		s.evictLocked()
		s.revision.Add(1)
		out := nf
		return &out, true
	}

	existing.generation = gen
	// Captured before LastSeen advances, so the location gate below can still ask
	// whether this sighting is newer than the one currently pointed at.
	prevLastSeen := existing.LastSeen
	if f.LastSeen.After(existing.LastSeen) {
		existing.LastSeen = f.LastSeen
	}
	if !f.FirstSeen.IsZero() && f.FirstSeen.Before(existing.FirstSeen) {
		existing.FirstSeen = f.FirstSeen
	}
	// Point at the most recent sighting, which is the one most likely still in
	// the ring buffer. Offset, length, and part describe one location and must be
	// updated together: a host-grouped rule can merge two different matches.
	//
	// Gated on the timestamp rather than on arrival: captures are scanned by a
	// worker pool, so the last result to reach this line is not the newest
	// sighting. Without the gate a host-grouped finding drifts to whichever
	// worker happened to finish last.
	newer := !f.LastSeen.Before(prevLastSeen) || existing.RequestID == ""
	if f.RequestID != "" && newer {
		existing.RequestID = f.RequestID
		existing.URL = f.URL
		existing.Method = f.Method
		existing.EvidenceOffset = f.EvidenceOffset
		existing.EvidenceLength = f.EvidenceLength
		existing.EvidencePart = f.EvidencePart
		// Evidence moves with the location it points at.
		existing.Evidence = f.Evidence
		existing.RawEvidence = f.RawEvidence
	}
	if existing.Evidence == "" {
		existing.Evidence = f.Evidence
	}
	// Adopt the incoming severity only when the operator has not overridden it.
	if !existing.SeverityOverridden && f.Severity != "" {
		existing.Severity = f.Severity
	}
	if f.Truncated {
		existing.Truncated = true
	}

	for _, o := range f.Occurrences {
		k := occKey(o)
		if _, counted := existing.occSeen[k]; counted {
			continue
		}
		if len(existing.occSeen) < maxOccSeen {
			existing.occSeen[k] = struct{}{}
		}
		existing.Count++
		existing.Occurrences = append(existing.Occurrences, o)
		if len(existing.Occurrences) > maxOccurrences {
			existing.Occurrences = existing.Occurrences[len(existing.Occurrences)-maxOccurrences:]
		}
	}

	s.revision.Add(1)
	out := *existing
	return &out, false
}

// evictLocked drops the oldest findings when over capacity.
func (s *Store) evictLocked() {
	for len(s.order) > s.maxItems {
		id := s.order[0]
		s.order = s.order[1:]
		delete(s.byID, id)
	}
}

// Get returns a copy of one finding.
func (s *Store) Get(id string) (Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.byID[id]
	if !ok {
		return Finding{}, false
	}
	return *f, true
}

// Update applies operator edits to a finding. Passing nil for a field leaves it
// unchanged, so a PUT can carry any subset.
func (s *Store) Update(id string, falsePositive *bool, notes *string, severity *Severity) (Finding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.byID[id]
	if !ok {
		return Finding{}, false
	}
	if falsePositive != nil {
		f.FalsePositive = *falsePositive
	}
	if notes != nil {
		f.Notes = *notes
	}
	if severity != nil && severity.Valid() {
		f.Severity = *severity
		f.SeverityOverridden = true
	}
	s.revision.Add(1)
	return *f, true
}

// Delete removes one finding.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return false
	}
	delete(s.byID, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	s.revision.Add(1)
	return true
}

// Clear removes every finding.
func (s *Store) Clear() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.byID)
	s.byID = map[string]*Finding{}
	s.order = nil
	s.skippedEncoded.Store(0)
	s.skippedBinary.Store(0)
	s.scanned.Store(0)
	s.revision.Add(1)
	return n
}

// DeleteFalsePositives removes only findings marked as false positives.
func (s *Store) DeleteFalsePositives() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []string
	n := 0
	for _, id := range s.order {
		f := s.byID[id]
		if f != nil && f.FalsePositive {
			delete(s.byID, id)
			n++
			continue
		}
		kept = append(kept, id)
	}
	s.order = kept
	if n > 0 {
		s.revision.Add(1)
	}
	return n
}

// PurgeBelowGeneration drops findings a scan pass did not re-confirm. Findings
// marked false-positive or carrying notes are always kept.
func (s *Store) PurgeBelowGeneration(gen uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []string
	n := 0
	for _, id := range s.order {
		f := s.byID[id]
		if f == nil {
			continue
		}
		if f.generation < gen && !f.FalsePositive && f.Notes == "" {
			delete(s.byID, id)
			n++
			continue
		}
		kept = append(kept, id)
	}
	s.order = kept
	if n > 0 {
		s.revision.Add(1)
	}
	return n
}

// Count returns the number of findings held.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// All returns copies of every finding, newest first.
func (s *Store) All() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Finding, 0, len(s.byID))
	for i := len(s.order) - 1; i >= 0; i-- {
		if f := s.byID[s.order[i]]; f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// Load replaces the store contents (project load). Findings keep the IDs they
// were persisted with; the ID is the dedupe identity.
func (s *Store) Load(findings []Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*Finding, len(findings))
	s.order = make([]string, 0, len(findings))
	for i := range findings {
		f := findings[i]
		if f.ID == "" {
			continue
		}
		if f.occSeen == nil {
			f.occSeen = map[string]struct{}{}
			for _, o := range f.Occurrences {
				f.occSeen[occKey(o)] = struct{}{}
			}
		}
		if _, dup := s.byID[f.ID]; dup {
			continue
		}
		s.byID[f.ID] = &f
		s.order = append(s.order, f.ID)
	}
	s.evictLocked()
	s.revision.Add(1)
}

// Summary aggregates the store for the header and the summary event. It takes
// the same rule-enabled predicate as List so the counts match the table.
func (s *Store) Summary(ruleEnabled func(string) bool) Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := Summary{
		BySeverity:     map[string]int{},
		ByCategory:     map[string]int{},
		SkippedEncoded: int(s.skippedEncoded.Load()),
		SkippedBinary:  int(s.skippedBinary.Load()),
		Scanned:        int(s.scanned.Load()),
	}
	for _, f := range s.byID {
		if f.FalsePositive {
			sum.FalsePositives++
			continue
		}
		if ruleEnabled != nil && !ruleEnabled(f.RuleID) {
			sum.HiddenByDisabledRule++
			continue
		}
		sum.Total++
		sum.BySeverity[string(f.Severity)]++
		sum.ByCategory[string(f.Category)]++
	}
	return sum
}

// List applies a filter and returns a page plus the total number of matches.
func (s *Store) List(f FindingFilter, ruleEnabled func(string) bool) ([]Finding, int) {
	s.mu.RLock()
	matched := make([]Finding, 0, len(s.byID))
	for _, item := range s.byID {
		if matchesFinding(item, f, ruleEnabled) {
			matched = append(matched, *item)
		}
	}
	s.mu.RUnlock()

	sortFindings(matched, f.Sort, f.Dir)

	total := len(matched)
	if f.Offset >= total {
		// Return an empty slice rather than nil so the JSON envelope emits [].
		return []Finding{}, total
	}
	page := matched[f.Offset:]
	if f.Limit > 0 && len(page) > f.Limit {
		page = page[:f.Limit]
	}
	out := make([]Finding, len(page))
	copy(out, page)
	return out, total
}

// matchesFinding applies every filter dimension.
func matchesFinding(f *Finding, filter FindingFilter, ruleEnabled func(string) bool) bool {
	switch strings.ToLower(filter.FP) {
	case "all":
	case "true":
		if !f.FalsePositive {
			return false
		}
	default: // "false" or empty
		if f.FalsePositive {
			return false
		}
	}

	if !filter.IncludeDisabled && ruleEnabled != nil && !ruleEnabled(f.RuleID) {
		return false
	}
	// An explicit severity selection overrides MinSeverity rather than combining
	// with it.
	switch {
	case len(filter.Severities) > 0:
		if !containsFold(filter.Severities, string(f.Severity)) {
			return false
		}
	case filter.MinSeverity != "":
		if f.Severity.Rank() < Severity(strings.ToLower(filter.MinSeverity)).Rank() {
			return false
		}
	}
	if len(filter.Categories) > 0 && !containsFold(filter.Categories, string(f.Category)) {
		return false
	}
	if filter.Confidence != "" && !strings.EqualFold(filter.Confidence, string(f.Confidence)) {
		return false
	}
	if filter.RuleID != "" {
		needle := strings.ToLower(filter.RuleID)
		if !strings.Contains(strings.ToLower(f.RuleID), needle) &&
			!strings.Contains(strings.ToLower(f.RuleName), needle) {
			return false
		}
	}
	if filter.Host != "" && !strings.Contains(strings.ToLower(f.Host), strings.ToLower(filter.Host)) {
		return false
	}
	if filter.Search != "" {
		needle := strings.ToLower(filter.Search)
		if !strings.Contains(strings.ToLower(f.Evidence), needle) &&
			!strings.Contains(strings.ToLower(f.URL), needle) &&
			!strings.Contains(strings.ToLower(f.RuleName), needle) &&
			!strings.Contains(strings.ToLower(f.Detail), needle) &&
			!strings.Contains(strings.ToLower(f.Notes), needle) {
			return false
		}
	}
	return true
}

// containsFold reports whether list contains v, case-insensitively.
func containsFold(list []string, v string) bool {
	for _, item := range list {
		if strings.EqualFold(item, v) {
			return true
		}
	}
	return false
}

// sortFindings orders results, defaulting to severity descending.
func sortFindings(items []Finding, key, dir string) {
	desc := !strings.EqualFold(dir, "asc")
	less := func(i, j int) bool {
		a, b := items[i], items[j]
		var cmp int
		switch strings.ToLower(key) {
		case "lastseen":
			cmp = compareTime(a.LastSeen, b.LastSeen)
		case "firstseen":
			cmp = compareTime(a.FirstSeen, b.FirstSeen)
		case "count":
			cmp = a.Count - b.Count
		case "host":
			cmp = strings.Compare(a.Host, b.Host)
		case "rule":
			cmp = strings.Compare(a.RuleName, b.RuleName)
		default: // severity
			cmp = a.Severity.Rank() - b.Severity.Rank()
		}
		if cmp == 0 {
			// Deterministic tiebreak, so pagination stays coherent across requests.
			if c := a.Severity.Rank() - b.Severity.Rank(); c != 0 {
				cmp = c
			} else if c := compareTime(a.LastSeen, b.LastSeen); c != 0 {
				cmp = c
			} else {
				cmp = strings.Compare(a.ID, b.ID)
			}
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	}
	sort.SliceStable(items, less)
}

// compareTime returns -1, 0, or 1.
func compareTime(a, b time.Time) int {
	switch {
	case a.Before(b):
		return -1
	case a.After(b):
		return 1
	default:
		return 0
	}
}
