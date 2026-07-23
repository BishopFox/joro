package mythic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// MythicEvent is emitted when a new callback appears. Broadcast to the UI as the
// "mythic.event" WS event (mirrors sliver.SliverEvent).
type MythicEvent struct {
	EventType string       `json:"eventType"` // e.g. "callback-new"
	Callback  CallbackInfo `json:"callback,omitempty"`
}

// graphql-ws (legacy apollo subscriptions-transport-ws) message envelope.
type wsMessage struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// startEventsStream opens a Hasura graphql-ws subscription over WebSocket and
// emits a MythicEvent for each newly-appearing active callback. The subscription
// re-pushes the callback set on change; we track seen display_ids and only fire
// for new ones — avoids the cursor bookkeeping of a streaming subscription while
// staying robust across Mythic versions.
func (c *Client) startEventsStream() {
	c.mu.Lock()
	base, token, isAPI := c.baseURL, c.token, c.isAPIToken
	ctx, cancel := context.WithCancel(context.Background())
	c.subCancel = cancel
	c.mu.Unlock()

	wsURL := toWebSocketURL(base) + "/graphql/"
	go c.runSubscription(ctx, wsURL, token, isAPI)
}

func (c *Client) runSubscription(ctx context.Context, wsURL, token string, isAPI bool) {
	dialer := websocket.Dialer{
		Subprotocols:     []string{"graphql-ws"},
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 15 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Close the socket when the context is cancelled (Disconnect).
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// connection_init with auth headers in the payload (Hasura ws auth).
	authHeader := map[string]string{}
	if isAPI {
		authHeader["apitoken"] = token
	} else {
		authHeader["Authorization"] = "Bearer " + token
	}
	initPayload, _ := json.Marshal(map[string]any{"headers": authHeader})
	if err := conn.WriteJSON(wsMessage{Type: "connection_init", Payload: initPayload}); err != nil {
		return
	}

	const subQuery = `subscription NewCallbacks {
		callback(where: {active: {_eq: true}}, order_by: {id: desc}, limit: 10) {
			id display_id user host pid ip os architecture last_checkin description
			payload { payloadtype { name } }
		}
	}`

	seen := make(map[int]bool)
	firstBatch := true

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var msg wsMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}

		switch msg.Type {
		case "connection_ack":
			startPayload, _ := json.Marshal(map[string]any{"query": subQuery})
			if err := conn.WriteJSON(wsMessage{ID: "1", Type: "start", Payload: startPayload}); err != nil {
				return
			}
		case "ka", "connection_keep_alive":
			// heartbeat, ignore
		case "data":
			var p struct {
				Data struct {
					Callback []struct {
						ID           int    `json:"id"`
						DisplayID    int    `json:"display_id"`
						User         string `json:"user"`
						Host         string `json:"host"`
						PID          int    `json:"pid"`
						IP           string `json:"ip"`
						OS           string `json:"os"`
						Architecture string `json:"architecture"`
						LastCheckin  string `json:"last_checkin"`
						Description  string `json:"description"`
						Payload      struct {
							PayloadType struct {
								Name string `json:"name"`
							} `json:"payloadtype"`
						} `json:"payload"`
					} `json:"callback"`
				} `json:"data"`
			}
			if err := json.Unmarshal(msg.Payload, &p); err != nil {
				continue
			}
			for _, cb := range p.Data.Callback {
				if seen[cb.ID] {
					continue
				}
				seen[cb.ID] = true
				// Prime the seen-set on the first snapshot without alerting for
				// callbacks that already existed before we connected.
				if firstBatch {
					continue
				}
				c.emit(MythicEvent{
					EventType: "callback-new",
					Callback: CallbackInfo{
						ID: cb.ID, DisplayID: cb.DisplayID, User: cb.User, Host: cb.Host,
						PID: cb.PID, IP: cb.IP, OS: cb.OS, Architecture: cb.Architecture,
						LastCheckin: cb.LastCheckin, Description: cb.Description,
						PayloadType: cb.Payload.PayloadType.Name,
					},
				})
			}
			firstBatch = false
		case "error", "connection_error":
			return
		case "complete":
			return
		}
	}
}

// emit forwards an event to the registered onEvent callback.
func (c *Client) emit(ev MythicEvent) {
	c.mu.Lock()
	fn := c.onEvent
	c.mu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

// toWebSocketURL converts an http(s) base URL to its ws(s) equivalent.
func toWebSocketURL(base string) string {
	if strings.HasPrefix(base, "https://") {
		return "wss://" + strings.TrimPrefix(base, "https://")
	}
	if strings.HasPrefix(base, "http://") {
		return "ws://" + strings.TrimPrefix(base, "http://")
	}
	return base
}
