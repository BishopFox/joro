package mcp

import "slices"

// ProtocolVersion is the MCP revision this server advertises when a client asks
// for one it does not recognize.
//
// Because the protocol layer here is hand-rolled, this constant and
// supportedVersions are the whole of the version surface — bumping support means
// editing this file and nothing else. Keep it that way.
const ProtocolVersion = "2025-06-18"

// supportedVersions are the revisions we will echo back if a client asks for
// them. All three carry the same tools/list and tools/call shapes, which is the
// entire surface this server implements; nothing below depends on which is in use.
var supportedVersions = []string{
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// negotiate picks the version to report in the initialize result.
//
// Preferring the client's requested version when we recognize it, rather than
// always answering with our own, is what lets an older client work unchanged.
func negotiate(requested string) string {
	if slices.Contains(supportedVersions, requested) {
		return requested
	}
	return ProtocolVersion
}

// serverName and serverVersion identify Joro in the initialize result.
const serverName = "joro"

// initializeResult is the reply to initialize.
type initializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    serverCapabilities `json:"capabilities"`
	ServerInfo      serverInfo         `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

type serverCapabilities struct {
	Tools *toolsCapability `json:"tools,omitempty"`
}

type toolsCapability struct {
	// ListChanged is false and must stay false: this transport is POST-only, so
	// there is no channel on which to push a notification when an operator edits
	// a token's grants. Advertising it would promise something undeliverable. A
	// client sees a grant change on its next tools/list.
	ListChanged bool `json:"listChanged"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// instructions is prepended to the model's context by most clients. It is the one
// place to say what this server is for and what the cheap path through it looks
// like, so an agent does not learn that by trial and error at the operator's
// token expense.
const instructions = `Joro is an intercepting HTTP proxy used for authorized security testing. These tools read
traffic it has already captured, and (if granted) replay edited requests through it.

Requests are addressed by their integer seq, from history_list. Nothing returns a full
response body by default, because bodies are large: use http_fingerprint to compare responses,
http_search to find a string across many of them, http_read for a specific byte range, and
http_diff to see what changed between two. Reach for a body only when a range or a diff cannot
answer the question.

http_resend and http_batch send real traffic to a real target through the proxy, so the result
appears in the operator's history. They are refused for hosts outside the configured scope.`
