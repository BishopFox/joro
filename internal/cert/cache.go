package cert

import (
	"crypto/tls"
	"sync"
	"time"
)

// Cache caches leaf TLS certificates per hostname to avoid regenerating them on every connection.
type Cache struct {
	ca    *CA
	store sync.Map // map[string]*tls.Certificate
}

// NewCache creates a Cache backed by the given CA.
func NewCache(ca *CA) *Cache {
	return &Cache{ca: ca}
}

// Get returns a cached leaf cert for hostname, generating one if needed.
// A cached cert within an hour of its NotAfter is discarded and regenerated, so
// a long-running proxy never serves an expired leaf from the cache.
func (c *Cache) Get(hostname string) (*tls.Certificate, error) {
	if v, ok := c.store.Load(hostname); ok {
		cert := v.(*tls.Certificate)
		if cert.Leaf != nil && time.Now().Before(cert.Leaf.NotAfter.Add(-time.Hour)) {
			return cert, nil
		}
		// Expired or nearing expiry — drop it and regenerate below.
		c.store.Delete(hostname)
	}

	cert, err := GenerateLeaf(c.ca, hostname)
	if err != nil {
		return nil, err
	}

	// Store with compare-and-swap to avoid thundering herd overwrites.
	actual, _ := c.store.LoadOrStore(hostname, cert)
	return actual.(*tls.Certificate), nil
}
