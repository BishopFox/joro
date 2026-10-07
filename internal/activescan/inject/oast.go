package inject

import (
	"context"
	"time"

	"github.com/BishopFox/joro/internal/callback"
)

// OASTAvailable reports whether out-of-band testing can run: a callback store with
// a configured domain. When false, rules skip their OAST vectors rather than emit a
// payload to an unresolvable domain — OAST is disabled unless a listener/team
// server provides a callback domain.
func OASTAvailable(store *callback.Store) bool {
	if store == nil {
		return false
	}
	cfg, err := store.GetConfig()
	return err == nil && cfg != nil && cfg.Domain != ""
}

// OAST mints callback tokens and polls for interactions, for blind detection.
type OAST struct {
	store  *callback.Store
	domain string
}

// NewOAST returns an OAST helper, or nil when OAST is unavailable (caller skips).
func NewOAST(store *callback.Store) *OAST {
	if !OASTAvailable(store) {
		return nil
	}
	cfg, _ := store.GetConfig()
	return &OAST{store: store, domain: cfg.Domain}
}

// Token mints a correlation token and returns it with the callback hostname to
// weave into a payload (`<token>.<domain>`).
func (o *OAST) Token(note string) (tokenID, host string, err error) {
	tok, err := callback.GenerateToken(o.store, note)
	if err != nil {
		return "", "", err
	}
	return tok.ID, tok.Token + "." + o.domain, nil
}

// Fired polls the callback store until an interaction for tokenID appears or the
// window elapses, respecting ctx. It returns true on the first hit.
func (o *OAST) Fired(ctx context.Context, tokenID string, window time.Duration) bool {
	deadline := time.Now().Add(window)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		if items, _, err := o.store.ListInteractions(tokenID, 0, 1); err == nil && len(items) > 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
