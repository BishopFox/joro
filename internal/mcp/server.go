package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/BishopFox/joro/internal/automation"
	"github.com/BishopFox/joro/internal/capability"
)

// maxBodyBytes bounds a single JSON-RPC request. Tool arguments are small —
// http_batch's fifty labelled variants is the largest realistic payload — so this
// is generous while still bounding an accidental or hostile upload.
const maxBodyBytes = 4 << 20

// Server implements the MCP endpoint over a capability registry.
//
// It holds no state per client: there is no session id and no subscription. The
// registry is the authority on what exists, the token store on who is asking, and
// this type only translates between JSON-RPC and those two.
type Server struct {
	reg    *capability.Registry
	tokens *automation.Store
	// version is Joro's build version, reported in serverInfo.
	version string
}

func NewServer(reg *capability.Registry, tokens *automation.Store, version string) *Server {
	return &Server{reg: reg, tokens: tokens, version: version}
}

// Handler returns the fully wrapped handler: rebinding guard, then bearer auth,
// then the JSON-RPC endpoint.
//
// This is mounted on its own mux by the listener. /api/v1/* deliberately does not
// exist on that mux, so an automation token has no route by which to reach token
// or grant administration — those live behind the same-origin UI API on a
// different port.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/mcp", automation.AuthMiddleware(s.tokens, http.HandlerFunc(s.serveRPC)))
	return loopbackGuard(mux)
}

func (s *Server) serveRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Streamable HTTP allows a server that never initiates messages to refuse
		// the SSE channel. We have nothing to push — see toolsCapability.
		w.Header().Set("Allow", "POST")
		http.Error(w, "this MCP server is POST-only; it initiates no server-to-client messages", http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeRPC(w, http.StatusRequestEntityTooLarge, errResponse(nil, newError(CodeInvalidRequest, "request body too large")))
		return
	}

	reqs, isBatch, err := decodeBatch(body)
	if err != nil {
		writeRPC(w, http.StatusBadRequest, errResponse(nil, newError(CodeParseError, "parse error: "+err.Error())))
		return
	}

	tok := automation.TokenFromContext(r.Context())
	if tok == nil {
		// AuthMiddleware guarantees this, but a nil principal would silently
		// authorize nothing rather than failing, so make it explicit.
		writeRPC(w, http.StatusUnauthorized, errResponse(nil, newError(CodeInvalidRequest, "unauthorized")))
		return
	}

	var out []*response
	for i := range reqs {
		resp := s.dispatch(r, tok, &reqs[i])
		if resp != nil {
			out = append(out, resp)
		}
	}

	// A batch consisting only of notifications gets 202 with no body, which is
	// what the specification asks for and what clients expect after sending
	// notifications/initialized.
	if len(out) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if isBatch {
		writeRPC(w, http.StatusOK, out)
		return
	}
	writeRPC(w, http.StatusOK, out[0])
}

func (s *Server) dispatch(r *http.Request, tok *automation.Token, req *request) *response {
	// A notification never gets a reply, not even an error one.
	notification := req.isNotification()
	reply := func(resp *response) *response {
		if notification {
			return nil
		}
		return resp
	}

	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return reply(errResponse(req.ID, newError(CodeInvalidRequest, `jsonrpc must be "2.0"`)))
	}

	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params) //nolint:errcheck // absent params is fine
		return reply(okResponse(req.ID, initializeResult{
			ProtocolVersion: negotiate(params.ProtocolVersion),
			Capabilities:    serverCapabilities{Tools: &toolsCapability{ListChanged: false}},
			ServerInfo:      serverInfo{Name: serverName, Version: s.version},
			Instructions:    instructions,
		}))

	case "notifications/initialized", "notifications/cancelled":
		return nil

	case "ping":
		return reply(okResponse(req.ID, map[string]any{}))

	case "tools/list":
		return reply(okResponse(req.ID, s.listTools(tok)))

	case "tools/call":
		return reply(s.callTool(r, tok, req))

	default:
		return reply(errResponse(req.ID, newError(CodeMethodNotFound, "unknown method: "+req.Method)))
	}
}

// listTools returns only the tools this token was granted.
//
// Filtering here rather than refusing on call is the point of the design: an
// ungranted capability is not merely denied, it is never named, so it does not
// consume the model's context or invite an attempt.
func (s *Server) listTools(tok *automation.Token) listToolsResult {
	caps := s.reg.List(tok.Principal())
	tools := make([]tool, 0, len(caps))
	for _, c := range caps {
		tools = append(tools, toolFor(c))
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return listToolsResult{Tools: tools}
}

func (s *Server) callTool(r *http.Request, tok *automation.Token, req *request) *response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errResponse(req.ID, newError(CodeInvalidParams, "invalid params: "+err.Error()))
	}
	if params.Name == "" {
		return errResponse(req.ID, newError(CodeInvalidParams, "name is required"))
	}

	capID := capIDFromTool(params.Name)
	principal := tok.Principal()

	// Authorization is left entirely to Invoke, which returns the same error for an
	// unknown tool as for an ungranted one — so tools/call still cannot be used to
	// enumerate capabilities this token was not given — and, crucially, writes an
	// audit entry from a defer. A pre-check here duplicated that decision while
	// bypassing the log, which meant an agent probing for tools it had not been
	// granted left no trace in Activity: the one place the audit log's own doc comment
	// says such probing shows up.
	res, err := s.reg.Invoke(r.Context(), principal, capID, params.Arguments)

	// Record use even on failure: a token being denied repeatedly is exactly the
	// pattern an operator wants to see in Activity, and last-used should reflect
	// attempts, not just successes.
	s.tokens.Touch(tok.ID, capID, time.Now())

	if err != nil {
		return okResponse(req.ID, toolError(err))
	}
	return okResponse(req.ID, resultContent(res.Data))
}

func writeRPC(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload) //nolint:errcheck
}
