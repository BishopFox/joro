// Package cdp is a minimal Chrome DevTools Protocol client: JSON-RPC 2.0 over a
// single WebSocket to a locally launched headless browser.
//
// It is hand-rolled on gorilla/websocket rather than vendoring chromedp or rod,
// the same choice internal/mcp (a hand-rolled JSON-RPC server) and the C2 clients
// make — the surface needed here is a handful of methods and two events, and a
// browser-automation dependency tree is a large supply-chain cost for that.
//
// # Threat model
//
// The client only ever connects to 127.0.0.1 on a port Joro itself just launched
// a browser with. A DevTools endpoint is unauthenticated and grants full control
// of the browser, so it must never be exposed off the loopback interface; the
// launch flags in internal/browser bind it to 127.0.0.1 and the dialer here
// refuses anything else. This mirrors the MCP listener's loopback-only posture.
//
// # Flat session
//
// The client attaches directly to one page target's debugger URL, so every
// command and event is for that page and no sessionId plumbing is needed. Driving
// several tabs would need Target.setAutoAttach and per-target sessions; a scan
// drives one page in sequence, so it does not.
package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client is a connection to one page target.
type Client struct {
	conn *websocket.Conn

	mu       sync.Mutex
	nextID   int
	pending  map[int]chan rpcResponse
	handlers map[string][]func(json.RawMessage)
	closed   bool
}

// rpcRequest is one outbound JSON-RPC command.
type rpcRequest struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

// rpcResponse is a reply or an event. A message with an id is a reply to the
// command that carried that id; one without is an event named by Method.
type rpcResponse struct {
	ID     int             `json:"id,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("cdp error %d: %s", e.Code, e.Message) }

// targetInfo is one entry of the /json listing.
type targetInfo struct {
	Type                 string `json:"type"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// Connect discovers the page target on a loopback DevTools endpoint and opens a
// WebSocket to it. debugPort is the --remote-debugging-port the browser was
// launched with.
func Connect(ctx context.Context, debugPort int, timeout time.Duration) (*Client, error) {
	wsURL, err := discoverPageWS(ctx, debugPort, timeout)
	if err != nil {
		return nil, err
	}

	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	// Modern Chrome rejects a CDP WebSocket whose Origin is not allowlisted; the
	// browser is launched with --remote-allow-origins=* (loopback only), and the
	// matching Origin header is sent here.
	hdr := http.Header{"Origin": {fmt.Sprintf("http://127.0.0.1:%d", debugPort)}}
	conn, _, err := dialer.DialContext(ctx, wsURL, hdr)
	if err != nil {
		return nil, fmt.Errorf("cdp dial: %w", err)
	}

	c := &Client{
		conn:     conn,
		pending:  make(map[int]chan rpcResponse),
		handlers: make(map[string][]func(json.RawMessage)),
	}
	go c.readLoop()
	return c, nil
}

// discoverPageWS polls http://127.0.0.1:<port>/json until a page target appears,
// returning its WebSocket debugger URL. The browser writes the port and the
// listing only once it is ready, so a short poll is simpler than racing it.
func discoverPageWS(ctx context.Context, port int, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/json", port)
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		ws, err := fetchPageWS(ctx, endpoint)
		if err == nil && ws != "" {
			return ws, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("cdp discovery timed out: %w", lastErr)
	}
	return "", fmt.Errorf("cdp discovery timed out: no page target on port %d", port)
}

func fetchPageWS(ctx context.Context, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var targets []targetInfo
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebuggerURL != "" {
			if _, err := url.Parse(t.WebSocketDebuggerURL); err == nil {
				return t.WebSocketDebuggerURL, nil
			}
		}
	}
	return "", nil
}

// readLoop dispatches replies to their waiting caller and events to handlers.
func (c *Client) readLoop() {
	for {
		var msg rpcResponse
		if err := c.conn.ReadJSON(&msg); err != nil {
			c.fail()
			return
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.pending[msg.ID]
			delete(c.pending, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		if msg.Method != "" {
			c.mu.Lock()
			hs := append([]func(json.RawMessage){}, c.handlers[msg.Method]...)
			c.mu.Unlock()
			for _, h := range hs {
				h(msg.Params)
			}
		}
	}
}

// fail wakes every pending caller when the socket dies, so a Send cannot hang
// past the connection.
func (c *Client) fail() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

// Send issues a command and waits for its reply (or the context's deadline).
func (c *Client) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("cdp: connection closed")
	}
	c.nextID++
	id := c.nextID
	ch := make(chan rpcResponse, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	if err := c.conn.WriteJSON(rpcRequest{ID: id, Method: method, Params: params}); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("cdp write %s: %w", method, err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("cdp: connection closed during %s", method)
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	}
}

// On registers a handler for a CDP event, e.g. "Runtime.bindingCalled". Handlers
// run on the read loop, so they must not block.
func (c *Client) On(method string, fn func(params json.RawMessage)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[method] = append(c.handlers[method], fn)
}

// Close tears down the socket.
func (c *Client) Close() {
	c.mu.Lock()
	already := c.closed
	c.closed = true
	c.mu.Unlock()
	if !already {
		_ = c.conn.Close()
	}
}
