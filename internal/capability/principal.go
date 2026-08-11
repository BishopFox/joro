package capability

// Principal is an authenticated automation caller, as the registry sees it.
//
// It is deliberately a plain value with no reference back to the token store.
// internal/automation builds one from a Token; this package never learns that
// tokens exist, which is what makes grant administration unreachable from a
// capability handler rather than merely absent from the registry.
type Principal struct {
	// TokenID and TokenName identify the caller in the audit log. TokenName is
	// snapshotted into each entry so a revoked token's history still reads.
	TokenID   string
	TokenName string

	// Grants is the fully expanded set of capability IDs this principal may
	// invoke. There are no wildcards here, by design — see the Grants discussion
	// in internal/automation. An empty set means the principal can do nothing.
	Grants map[string]struct{}

	// RequireScope makes send-capable capabilities fail closed unless Joro's scope
	// is enabled, has at least one rule, and matches the target. See guard.go.
	RequireScope bool

	// HostAllow is an optional list of host globs that ANDs with the scope check.
	// Empty means no additional restriction. It never widens: a whitelist that
	// could override a disabled scope would reintroduce the failure mode
	// RequireScope exists to close.
	HostAllow []string

	// Per-principal limits. Zero means the registry default.
	RateLimitPerMin int
	MaxConcurrent   int
	MaxOutputBytes  int
}

// Can reports whether this principal holds a grant for the given capability ID.
func (p Principal) Can(id string) bool {
	if p.Grants == nil {
		return false
	}
	_, ok := p.Grants[id]
	return ok
}
