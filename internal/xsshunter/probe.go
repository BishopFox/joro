package xsshunter

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateProbe creates a new probe with a random 16-char hex identifier.
func GenerateProbe(store *Store, name string) (*Probe, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	probeHex := hex.EncodeToString(b)

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	idStr := hex.EncodeToString(id)

	return store.CreateProbe(idStr, name, probeHex)
}
