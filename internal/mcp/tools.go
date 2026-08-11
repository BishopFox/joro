package mcp

import (
	"encoding/json"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
)

// toolName maps a capability ID to an MCP tool name.
//
// Capability IDs are dotted, which is the natural namespace and matches how the
// rest of this codebase names things. Several MCP clients reject a dot in a tool
// name, so dots become underscores. The round trip is total only because no
// capability ID may contain an underscore — capability.Register enforces that via
// its ID pattern, and a test in internal/capreg pins it.
//
// There is deliberately no "joro_" prefix. Clients already namespace tools by
// server, and every tool name sits in the model's context on every single turn.
func toolName(capID string) string {
	return strings.ReplaceAll(capID, ".", "_")
}

func capIDFromTool(name string) string {
	return strings.ReplaceAll(name, "_", ".")
}

// tool is the MCP tool definition.
type tool struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	InputSchema json.RawMessage  `json:"inputSchema"`
	Annotations *toolAnnotations `json:"annotations,omitempty"`
}

// toolAnnotations are advisory hints clients use to decide whether to prompt.
// They are hints, not enforcement: the registry's guard is what actually stops a
// call, and a client that ignores these gets refused there instead.
type toolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	IdempotentHint  bool `json:"idempotentHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

func toolFor(c capability.Capability) tool {
	readOnly := !c.Mutating && !c.SendsTraffic
	return tool{
		Name:        toolName(c.ID),
		Title:       c.Title,
		Description: c.Description,
		InputSchema: c.InputSchema,
		Annotations: &toolAnnotations{
			ReadOnlyHint: readOnly,
			// A send is marked destructive because it reaches a real target: the
			// request may change state there, and that is outside Joro's control.
			DestructiveHint: c.SendsTraffic || c.Mutating,
			IdempotentHint:  readOnly,
			OpenWorldHint:   c.SendsTraffic,
		},
	}
}

// listToolsResult is the tools/list reply. NextCursor is always empty: thirteen
// tools do not need paging, and a cursor a client must round-trip is one more
// thing to get wrong.
type listToolsResult struct {
	Tools []tool `json:"tools"`
}

// callToolResult is the tools/call reply.
type callToolResult struct {
	Content           []contentBlock `json:"content"`
	StructuredContent any            `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(s string) *callToolResult {
	return &callToolResult{Content: []contentBlock{{Type: "text", Text: s}}}
}

// toolError reports a failed invocation as a *successful* JSON-RPC response
// carrying isError.
//
// That is deliberate and it matters. An isError result stays in the model's
// conversation, so the model reads why it failed and corrects itself. A JSON-RPC
// error is handled by the client's transport layer and may never reach the model
// at all, which turns a fixable mistake — a bad seq, an out-of-scope host — into a
// silent dead end.
func toolError(err error) *callToolResult {
	return &callToolResult{
		Content: []contentBlock{{Type: "text", Text: "error: " + err.Error()}},
		IsError: true,
	}
}

// resultContent renders a capability's return value.
//
// Tools in internal/httptools return pre-rendered text tables, which is the whole
// token-efficiency argument, so a string passes straight through. Anything else is
// marshalled compactly.
//
// structuredContent is emitted only for a single fixed-shape object, never for a
// list. A client that renders both the text and the structured form would double
// the cost of a forty-row table, which defeats the point of the tables existing.
func resultContent(data any) *callToolResult {
	switch v := data.(type) {
	case string:
		return textResult(v)
	case nil:
		return textResult("(no result)")
	}
	b, err := json.Marshal(data)
	if err != nil {
		return toolError(err)
	}
	res := textResult(string(b))
	if isSmallObject(data) {
		res.StructuredContent = data
	}
	return res
}

// isSmallObject reports whether a value is a single map or struct small enough
// that duplicating it as structuredContent is affordable.
func isSmallObject(data any) bool {
	m, ok := data.(map[string]any)
	if !ok {
		return false
	}
	return len(m) <= 30
}
