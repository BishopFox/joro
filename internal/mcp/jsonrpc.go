// Package mcp implements a Model Context Protocol server over the capability
// registry.
//
// Joro speaks MCP as a server. It embeds no model, makes no outbound AI calls and
// holds no provider credentials — an automation client connects to Joro, not the
// other way round.
//
// The JSON-RPC layer is hand-rolled rather than taken from an SDK, matching how
// this repo already handles wire protocols: protowire for Sliver, BER for LDAP,
// WebSocket frames, GraphQL over plain HTTP for Mythic. The cost is that protocol
// revisions have to be tracked by hand; protocol.go isolates that to one file.
package mcp

import (
	"encoding/json"
	"errors"
)

// JSON-RPC 2.0 error codes. The first four are from the specification; -32002 is
// the MCP convention for a resource or tool that exists but is unavailable.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// request is one JSON-RPC call. ID is kept as a RawMessage so it can be echoed
// back byte for byte: the specification allows a string, a number or null, and
// round-tripping through any Go type risks changing 1 into 1.0.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether no response should be produced. A request with
// no id is a notification, and per the specification the server must not reply —
// including not replying with an error.
func (r *request) isNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

func newError(code int, msg string) *rpcError {
	return &rpcError{Code: code, Message: msg}
}

func okResponse(id json.RawMessage, result any) *response {
	return &response{JSONRPC: "2.0", ID: idOrNull(id), Result: result}
}

func errResponse(id json.RawMessage, err *rpcError) *response {
	return &response{JSONRPC: "2.0", ID: idOrNull(id), Error: err}
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// decodeBatch parses a request body, which may be a single object or an array.
// The bool reports whether the payload was a batch, so the reply is shaped to
// match: a client that sent one object must not receive a one-element array.
func decodeBatch(body []byte) (reqs []request, isBatch bool, err error) {
	trimmed := trimLeadingSpace(body)
	if len(trimmed) == 0 {
		return nil, false, errors.New("empty request body")
	}
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &reqs); err != nil {
			return nil, true, err
		}
		if len(reqs) == 0 {
			return nil, true, errors.New("empty batch")
		}
		return reqs, true, nil
	}
	var one request
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, false, err
	}
	return []request{one}, false, nil
}

func trimLeadingSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return b[i:]
}
