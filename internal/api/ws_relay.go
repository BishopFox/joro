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
		return
	}

	lr.url = listenerURL
	lr.token = token
	lr.nickname = nickname
	lr.stop = make(chan struct{})
	go lr.run(lr.stop, listenerURL, token, nickname)
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

		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			if resp != nil {
				log.Printf("team relay: connect error: %v (HTTP %d)", err, resp.StatusCode)
			} else {
				log.Printf("team relay: connect error: %v", err)
			}
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
		lr.readLoop(conn, stop)
		conn.Close()
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
