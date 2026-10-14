package feeds

import (
	"context"
	"sort"
	"sync"
	"time"
)

// FetchFunc performs a bounded GET and returns the body. Injected by the api layer so this
// package never imports internal/proxy; the implementation verifies TLS, follows no
// redirects, honors the operator's SOCKS dialer, and reads at most limitBytes.
type FetchFunc func(ctx context.Context, url string, limitBytes int64) ([]byte, error)

// perCategoryCap bounds how many items each category retains after a merge, so the rolling
// cache (and the snapshot the UI holds) stays a fixed, small size.
var perCategoryCap = map[Category]int{
	CategoryCVE:      60,
	CategoryKEV:      100,
	CategoryHeadline: 60,
}

// Aggregator holds the rolling, thread-safe snapshot and refreshes it from its sources.
//
// Refresh merges new items into a per-category rolling set rather than replacing it, so a
// 24-hour NVD window accumulates and a source that fails on one tick keeps its last-known
// items (only its SourceStatus goes stale). That "never blank the cache" rule is why the UI
// can show "stale since X" instead of an empty panel.
type Aggregator struct {
	mu        sync.RWMutex
	sources   []Source
	fetch     FetchFunc
	items     map[Category][]Item
	status    map[string]SourceStatus
	lastRun   time.Time
	generated time.Time
}

func NewAggregator(sources []Source, fetch FetchFunc) *Aggregator {
	a := &Aggregator{
		sources: sources,
		fetch:   fetch,
		items:   map[Category][]Item{},
		status:  map[string]SourceStatus{},
	}
	for _, s := range sources {
		a.status[s.ID] = SourceStatus{ID: s.ID, Name: s.Name, Category: s.Category}
	}
	return a
}

// Refresh fetches every source whose category is wanted (nil means all), sequentially so
// total egress stays a trickle, and returns the resulting snapshot. Safe to call
// concurrently with Snapshot and the HTTP handlers.
func (a *Aggregator) Refresh(ctx context.Context, want map[Category]bool) Snapshot {
	a.markRun()
	for _, src := range a.sources {
		if ctx.Err() != nil {
			break
		}
		if want != nil && !want[src.Category] {
			continue
		}
		items, err := src.collect(ctx, a.fetch)
		a.applyResult(src, items, err)
	}
	a.mu.Lock()
	a.generated = time.Now().UTC()
	a.mu.Unlock()

	a.recomputeKEVCrossLinks()
	// Enrich CVE + KEV items with EPSS scores (a clean join on the validated CVE id). Best
	// effort: a failure leaves the existing items unscored rather than failing the refresh.
	a.enrichEPSS(ctx)
	return a.Snapshot()
}

// markRun stamps the start of a run so a manual refresh is debounced against it immediately,
// before the (asynchronous) work begins.
func (a *Aggregator) markRun() {
	a.mu.Lock()
	a.lastRun = time.Now().UTC()
	a.mu.Unlock()
}

// TryBeginManual reports whether a manual refresh is allowed now, stamping the run clock when
// it is so two rapid clicks cannot both pass. The periodic loop uses Refresh directly.
func (a *Aggregator) TryBeginManual(min time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.lastRun.IsZero() && time.Since(a.lastRun) < min {
		return false
	}
	a.lastRun = time.Now().UTC()
	return true
}

func (a *Aggregator) applyResult(src Source, items []Item, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.status[src.ID]
	st.LastAttempt = time.Now().UTC()
	if err != nil {
		// Keep-last-known: leave a.items[category] untouched and only mark the source stale.
		st.LastError = sanitizeText(err.Error(), maxError)
		st.Stale = true
		a.status[src.ID] = st
		return
	}
	// Stamp the trusted source name and category over anything the parser set, then merge.
	for i := range items {
		items[i].Source = src.Name
		items[i].Category = src.Category
	}
	merged := mergeItems(a.items[src.Category], items, perCategoryCap[src.Category])
	a.items[src.Category] = merged
	st.LastError = ""
	st.LastSuccess = st.LastAttempt
	st.Stale = false
	st.ItemCount = countBySource(merged, src.Name)
	a.status[src.ID] = st
}

// recomputeKEVCrossLinks flags CVE-ticker items that also appear in the KEV catalog, joining
// only on the validated CVE id (a scalar), never on any feed content.
func (a *Aggregator) recomputeKEVCrossLinks() {
	a.mu.Lock()
	defer a.mu.Unlock()
	inKEV := make(map[string]bool, len(a.items[CategoryKEV]))
	for _, k := range a.items[CategoryKEV] {
		inKEV[k.ID] = true
	}
	for i := range a.items[CategoryCVE] {
		a.items[CategoryCVE][i].AlsoInKEV = inKEV[a.items[CategoryCVE][i].ID]
	}
}

// Snapshot returns a deep copy of the current state. All three category keys are always
// present (possibly empty arrays) so the client never indexes nil.
func (a *Aggregator) Snapshot() Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()
	items := make(map[Category][]Item, len(allCategories))
	for _, cat := range allCategories {
		list := a.items[cat]
		cp := make([]Item, len(list))
		copy(cp, list)
		items[cat] = cp
	}
	sources := make([]SourceStatus, 0, len(a.sources))
	for _, src := range a.sources {
		sources = append(sources, a.status[src.ID])
	}
	return Snapshot{Items: items, Sources: sources, GeneratedAt: a.generated}
}

// mergeItems folds incoming items into existing ones, deduping by id (incoming wins),
// sorting newest-first, and capping the result.
func mergeItems(existing, incoming []Item, cap int) []Item {
	byID := make(map[string]Item, len(existing)+len(incoming))
	order := make([]string, 0, len(existing)+len(incoming))
	add := func(it Item) {
		if it.ID == "" {
			return
		}
		if _, ok := byID[it.ID]; !ok {
			order = append(order, it.ID)
		}
		byID[it.ID] = it
	}
	for _, it := range existing {
		add(it)
	}
	for _, it := range incoming {
		add(it)
	}
	out := make([]Item, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Published.After(out[j].Published)
	})
	if cap > 0 && len(out) > cap {
		out = out[:cap]
	}
	return out
}

func countBySource(items []Item, name string) int {
	n := 0
	for _, it := range items {
		if it.Source == name {
			n++
		}
	}
	return n
}
