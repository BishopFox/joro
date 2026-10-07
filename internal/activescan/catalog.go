package activescan

import (
	"sort"
	"sync"
)

// CatalogField is one labelled line in an item's read-only detail.
type CatalogField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// CatalogItem is one entry in a rule's catalog — a nuclei signature or an injection
// check. It carries the common columns plus a free-form Detail list, so the handler
// and UI are agnostic to the item kind.
type CatalogItem struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Severity    string         `json:"severity"`
	Confidence  string         `json:"confidence,omitempty"`
	Target      string         `json:"target,omitempty"`
	Description string         `json:"description,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Enabled     bool           `json:"enabled"`
	Detail      []CatalogField `json:"detail,omitempty"`
}

// Cataloger is implemented by a Rule that exposes a catalog of individually
// toggleable items (Template signatures, or an injection rule's checks). It is
// optional — a single-check rule like DOM XSS does not implement it. The
// enable/disable half is satisfied by embedding *DisabledSet.
type Cataloger interface {
	CatalogItems() []CatalogItem
	IsItemEnabled(id string) bool
	SetItemEnabled(id string, on bool)
	DisabledItems() []string
	SetDisabledItems(ids []string)
}

// DisabledSet is a reusable per-item disabled set (an absent id is enabled),
// mirroring the Registry's per-rule model at item granularity. Rules embed it to
// get four of the five Cataloger methods for free; it is per-project session state
// (applyProjectConfig sets it, buildProjectConfig reads it).
type DisabledSet struct {
	mu sync.RWMutex
	m  map[string]bool
}

// NewDisabledSet returns an empty set (everything enabled).
func NewDisabledSet() *DisabledSet { return &DisabledSet{m: map[string]bool{}} }

// IsItemEnabled reports whether an item runs (absent from the disabled set).
func (d *DisabledSet) IsItemEnabled(id string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.m[id]
}

// SetItemEnabled toggles one item's disabled-state.
func (d *DisabledSet) SetItemEnabled(id string, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if on {
		delete(d.m, id)
	} else {
		d.m[id] = true
	}
}

// DisabledItems returns the disabled ids, sorted — the set the project file persists.
func (d *DisabledSet) DisabledItems() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.m))
	for id := range d.m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// SetDisabledItems replaces the set, for a project restore. A nil slice clears it.
func (d *DisabledSet) SetDisabledItems(ids []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.m = make(map[string]bool, len(ids))
	for _, id := range ids {
		d.m[id] = true
	}
}
