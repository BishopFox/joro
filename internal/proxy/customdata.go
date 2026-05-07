package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
)

// CustomAddition defines a single piece of data to inject into requests.
type CustomAddition struct {
	ID    string `json:"id"`
	Type  string `json:"type"`  // "header", "query", "body"
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CustomData manages a set of additive request modifications.
type CustomData struct {
	mu      sync.RWMutex
	enabled bool
	items   []CustomAddition
}

// NewCustomData creates a disabled CustomData with no items.
func NewCustomData() *CustomData {
	return &CustomData{}
}

// IsEnabled reports whether custom data injection is active.
func (cd *CustomData) IsEnabled() bool {
	cd.mu.RLock()
	defer cd.mu.RUnlock()
	return cd.enabled
}

// SetEnabled enables or disables custom data injection.
func (cd *CustomData) SetEnabled(enabled bool) {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.enabled = enabled
}

// Items returns a copy of the current items.
func (cd *CustomData) Items() []CustomAddition {
	cd.mu.RLock()
	defer cd.mu.RUnlock()
	out := make([]CustomAddition, len(cd.items))
	copy(out, cd.items)
	return out
}

// SetItems replaces all custom data items.
func (cd *CustomData) SetItems(items []CustomAddition) {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.items = items
}

// AddItem adds a new item with a generated ID. Returns the item.
func (cd *CustomData) AddItem(typ, name, value string) CustomAddition {
	item := CustomAddition{
		ID:    GenerateID(),
		Type:  typ,
		Name:  name,
		Value: value,
	}
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.items = append(cd.items, item)
	return item
}

// RemoveItem deletes an item by ID. Returns true if found.
func (cd *CustomData) RemoveItem(id string) bool {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	for i, item := range cd.items {
		if item.ID == id {
			cd.items = append(cd.items[:i], cd.items[i+1:]...)
			return true
		}
	}
	return false
}

// applyCustomData applies custom data additions to an *http.Request.
func applyCustomData(cd *CustomData, r *http.Request) *http.Request {
	if cd == nil || !cd.IsEnabled() {
		return r
	}

	cd.mu.RLock()
	items := make([]CustomAddition, len(cd.items))
	copy(items, cd.items)
	cd.mu.RUnlock()

	for _, item := range items {
		switch item.Type {
		case "header":
			if !slices.Contains(r.Header.Values(item.Name), item.Value) {
				r.Header.Add(item.Name, item.Value)
			}
		case "query":
			existing := r.URL.Query()
			if !slices.Contains(existing[item.Name], item.Value) {
				param := url.QueryEscape(item.Name) + "=" + url.QueryEscape(item.Value)
				if r.URL.RawQuery == "" {
					r.URL.RawQuery = param
				} else {
					r.URL.RawQuery = r.URL.RawQuery + "&" + param
				}
			}
		case "body":
			var bodyBytes []byte
			if r.Body != nil {
				bodyBytes, _ = io.ReadAll(r.Body)
				r.Body.Close()
			}
			if !bytes.Contains(bodyBytes, []byte(item.Value)) {
				bodyBytes = append(bodyBytes, []byte(item.Value)...)
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
		}
	}

	return r
}
