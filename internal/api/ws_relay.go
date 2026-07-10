package api

import (
	"encoding/json"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ListenerRelay maintains a WebSocket connection to the remote teamserver
// and relays team.* events to the local Hub.
type ListenerRelay struct {
	hub  *Hub
	mu   sync.Mutex
	url  string
	token string
	nickname string
	stop chan struct{}
}

// NewListenerRelay creates a relay. Call Update() to start connecting.
func NewListenerRelay(hub *Hub) *ListenerRelay {
	return &ListenerRelay{hub: hub}
}

// SetNickname updates the cached nickname for the next reconnect, without closing the current connection.
func (lr *ListenerRelay) SetNickname(newNickname string) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	lr.nickname = newNickname
}

// Update sets the connection parameters and (re)starts the relay.
// Pass empty url or token to stop the relay.
func (lr *ListenerRelay) Update(listenerURL, token, nickname string) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	// Stop existing connection.
	if lr.stop != nil {
		close(lr.stop)
		lr.stop = nil
	}

	if listenerURL == "" || token == "" {
		if lr.hub != nil {
			lr.hub.ClearRelayState()
		}
		return
	}

	lr.url = listenerURL
	lr.token = token
	lr.nickname = nickname
	lr.stop = make(chan struct{})
	// Set "connecting" synchronously so the UI reflects the attempt immediately,
	// before the goroutine's first dial. run() re-asserts it (deduped) each loop.
	if lr.hub != nil {
		lr.hub.SetRelayState("connecting", "", 0)
	}
	go lr.run(lr.stop, listenerURL, token, nickname)
}

// setRelayState reports a relay state to the hub, but only while this run()
// goroutine is still current (its stop channel is open). A stale goroutine left
// over from a reconnect can be mid-backoff; this stops it from clobbering the
// new goroutine's state after the fact.
func (lr *ListenerRelay) setRelayState(stop chan struct{}, state, errStr string, httpStatus int) {
	select {
	case <-stop:
		return
	default:
	}
	if lr.hub != nil {
		lr.hub.SetRelayState(state, errStr, httpStatus)
	}
}

func (lr *ListenerRelay) run(stop chan struct{}, listenerURL, token, nickname string) {
	backoff := time.Second

	for {
		select {
		case <-stop:
			return
		default:
		}

		wsURL := buildWSURL(listenerURL, token, nickname)
		if wsURL == "" {
			return
		}

		lr.setRelayState(stop, "connecting", "", 0)

		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			httpStatus := 0
			if resp != nil {
				httpStatus = resp.StatusCode
				log.Printf("team relay: connect error: %v (HTTP %d)", err, resp.StatusCode)
			} else {
				log.Printf("team relay: connect error: %v", err)
			}
			lr.setRelayState(stop, "disconnected", err.Error(), httpStatus)
			select {
			case <-stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}

		backoff = time.Second
		lr.setRelayState(stop, "connected", "", 0)
		lr.readLoop(conn, stop)
		conn.Close()
		lr.setRelayState(stop, "disconnected", "connection closed", 0)
	}
}

func (lr *ListenerRelay) readLoop(conn *websocket.Conn, stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var msg struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		// Only relay team events.
		if !strings.HasPrefix(msg.Type, "team.") {
			continue
		}

		// Re-broadcast the raw event to local clients.
		var raw any
		if err := json.Unmarshal(data, &raw); err == nil {
			lr.hub.Broadcast() <- raw
		}
	}
}

func buildWSURL(listenerURL, token, nickname string) string {
	base := strings.TrimRight(listenerURL, "/")

	// Convert http(s) to ws(s).
	if strings.HasPrefix(base, "https://") {
		base = "wss://" + strings.TrimPrefix(base, "https://")
	} else if strings.HasPrefix(base, "http://") {
		base = "ws://" + strings.TrimPrefix(base, "http://")
	} else {
		base = "ws://" + base
	}

	u, err := url.Parse(base + "/ws")
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("token", token)
	if nickname != "" {
		q.Set("nickname", nickname)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
