package capability

import "strings"

// reservedPrefixes are capability-ID namespaces that must never be registered.
//
// Token issuance, grant editing, and MCP listener administration are UI-only by
// design: a token that can mint or widen tokens is not a boundary, it is a
// formality, and an automation client that can start a listener can outlive the
// operator's intent to run one.
//
// This list is the third of four layers, and the weakest — a capability named
// "project.rotate_credential" slips past it. The layers that actually carry the
// property are the import direction (internal/capability cannot import
// internal/automation, because the reverse import makes it a cycle), the Deps
// struct in internal/capreg (which is never handed the token store), and the
// separate MCP mux (on which /api/v1/* does not exist). This list plus the
// name-pattern assertion in the registry test catch the cases where someone builds
// a plausible-looking administrative capability out of components they do have.
var reservedPrefixes = []string{
	"automation.",
	"token.",
	"tokens.",
	"grant.",
	"grants.",
	"auth.",
	"capability.",
	"capabilities.",
	"mcp.",
	"registry.",
	"admin.",
}

// IsReserved reports whether an ID falls in a reserved namespace. Exported so the
// automation store can drop reserved grants when loading a hand-edited or
// downgraded file, and so the REST layer can reject them on create.
func IsReserved(id string) bool {
	lower := strings.ToLower(strings.TrimSpace(id))
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ReservedPrefixes returns a copy of the reserved namespace list, for tests and
// for the error message the REST layer shows when a grant is rejected.
func ReservedPrefixes() []string {
	out := make([]string, len(reservedPrefixes))
	copy(out, reservedPrefixes)
	return out
}
