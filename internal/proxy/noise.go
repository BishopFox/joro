package proxy

import (
	"path/filepath"
	"strings"
	"sync"
)

// NoisePattern defines a host pattern to filter as noise.
type NoisePattern struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
}

// NoiseFilter silently tunnels/forwards traffic matching known browser noise
// patterns (captive portal, telemetry, OCSP, etc.) without capture.
type NoiseFilter struct {
	mu       sync.RWMutex
	enabled  bool
	patterns []NoisePattern
}

// defaultNoisePatterns returns the curated list of common browser noise hosts.
func defaultNoisePatterns() []NoisePattern {
	hosts := []string{
		// Firefox / Mozilla
		"detectportal.firefox.com",
		"*.mozilla.com",
		"*.mozilla.org",
		"*.mozilla.net",
		"*.mozgcp.net",
		// Chrome
		"safebrowsing.googleapis.com",
		"safebrowsing-cache.google.com",
		"update.googleapis.com",
		"optimizationguide-pa.googleapis.com",
		"content-autofill.googleapis.com",
		"clients.google.com",
		"clients2.google.com",
		"clients4.google.com",
		// OCSP
		"ocsp.pki.goog",
		"ocsp.digicert.com",
		"ocsp.sectigo.com",
		"ocsp.usertrust.com",
		// Apple
		"captive.apple.com",
		// Microsoft
		"crl.microsoft.com",
	}
	patterns := make([]NoisePattern, len(hosts))
	for i, h := range hosts {
		patterns[i] = NoisePattern{ID: GenerateID(), Pattern: h}
	}
	return patterns
}

// NewNoiseFilter creates a NoiseFilter that is enabled by default with
// curated browser noise patterns.
func NewNoiseFilter() *NoiseFilter {
	return &NoiseFilter{
		enabled:  true,
		patterns: defaultNoisePatterns(),
	}
}

// IsEnabled reports whether noise filtering is active.
func (nf *NoiseFilter) IsEnabled() bool {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	return nf.enabled
}

// SetEnabled enables or disables noise filtering.
func (nf *NoiseFilter) SetEnabled(enabled bool) {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.enabled = enabled
}

// Patterns returns a copy of the current noise patterns.
func (nf *NoiseFilter) Patterns() []NoisePattern {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	out := make([]NoisePattern, len(nf.patterns))
	copy(out, nf.patterns)
	return out
}

// SetPatterns replaces all noise patterns.
func (nf *NoiseFilter) SetPatterns(patterns []NoisePattern) {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.patterns = patterns
}

// AddPattern adds a new noise pattern and returns it with a generated ID.
func (nf *NoiseFilter) AddPattern(pattern string) NoisePattern {
	p := NoisePattern{ID: GenerateID(), Pattern: pattern}
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.patterns = append(nf.patterns, p)
	return p
}

// RemovePattern deletes a pattern by ID. Returns true if found.
func (nf *NoiseFilter) RemovePattern(id string) bool {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	for i, p := range nf.patterns {
		if p.ID == id {
			nf.patterns = append(nf.patterns[:i], nf.patterns[i+1:]...)
			return true
		}
	}
	return false
}

// IsNoisy checks if a host matches any enabled noise pattern.
func (nf *NoiseFilter) IsNoisy(host string) bool {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	if !nf.enabled {
		return false
	}
	host = strings.ToLower(host)
	for _, p := range nf.patterns {
		matched, err := filepath.Match(strings.ToLower(p.Pattern), host)
		if err == nil && matched {
			return true
		}
	}
	return false
}
