package cert

import (
	"crypto/tls"
	"sync"
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
func (c *Cache) Get(hostname string) (*tls.Certificate, error) {
	if v, ok := c.store.Load(hostname); ok {
		return v.(*tls.Certificate), nil
	}

	cert, err := GenerateLeaf(c.ca, hostname)
	if err != nil {
		return nil, err
	}

	// Store with compare-and-swap to avoid thundering herd overwrites.
	actual, _ := c.store.LoadOrStore(hostname, cert)
	return actual.(*tls.Certificate), nil
}
