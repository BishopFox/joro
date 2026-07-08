package api

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsWriteTimeout bounds a single client write so one dead/slow connection can't
// stall the whole broadcast loop until the OS TCP timeout.
const wsWriteTimeout = 10 * time.Second

// upgrader allows non-browser clients (no Origin) and same-origin browser
// handshakes; cross-origin handshakes are rejected.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		if origin == "null" {
			return false
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(reqHostname(u.Host), reqHostname(r.Host))
	},
}

// errNicknameInUse is returned by Hub.Rename when the target nickname is already taken.
var errNicknameInUse = errors.New("nickname already in use")

// OnConnectFunc is called when a named user connects with their nickname and IP.
type OnConnectFunc func(nickname, ip string)

// presenceInfo holds a user's opt-in presence metadata, keyed by nickname.
type presenceInfo struct {
	Status    string // online | away | dnd | offline
	ProjectID string // "" unless the operator shares it
}

// presenceUser is a single entry in a team.presence broadcast.
type presenceUser struct {
	Nickname  string `json:"nickname"`
	Status    string `json:"status"`
	ProjectID string `json:"projectId"`
}

// Hub manages WebSocket clients and broadcasts events to all of them.
type Hub struct {
	mu           sync.RWMutex
	clients      map[*websocket.Conn]string // conn -> nickname ("" for non-team connections)
	presenceMeta map[string]presenceInfo    // nickname -> presence metadata
	broadcast    chan any
	onConnect    OnConnectFunc
	onDisconnect OnConnectFunc
}

// NewHub creates a Hub. Call Run() in a goroutine before accepting connections.
func NewHub() *Hub {
	return &Hub{
		clients:      make(map[*websocket.Conn]string),
		presenceMeta: make(map[string]presenceInfo),
		broadcast:    make(chan any, 512),
	}
}

// SetOnConnect sets a callback invoked when a named user connects.
func (h *Hub) SetOnConnect(fn OnConnectFunc) {
	h.onConnect = fn
}

// SetOnDisconnect sets a callback invoked when a named user disconnects.
func (h *Hub) SetOnDisconnect(fn OnConnectFunc) {
	h.onDisconnect = fn
}

// Run reads from the broadcast channel and fans out to all connected clients.
// It blocks until the channel is closed.
func (h *Hub) Run() {
	for msg := range h.broadcast {
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}

		// Run is the sole writer to client conns, so serialized writes here are
		// gorilla-safe. Bound each write with a deadline; on error, close the
		// conn so the client's ReadMessage loop in ServeWS runs its deferred
		// cleanup and deregisters it (we can't delete under RLock here).
		h.mu.RLock()
		for conn := range h.clients {
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Printf("ws write: %v", err)
				conn.Close()
			}
		}
		h.mu.RUnlock()
	}
}

// Broadcast returns the write-only broadcast channel.
func (h *Hub) Broadcast() chan<- any {
	return h.broadcast
}

// HasNickname returns true if a client with the given nickname is already connected.
func (h *Hub) HasNickname(nickname string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, nick := range h.clients {
		if nick == nickname {
			return true
		}
	}
	return false
}

// ActiveUsers returns a deduplicated list of connected nicknames (non-empty only).
func (h *Hub) ActiveUsers() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	seen := make(map[string]struct{})
	var users []string
	for _, nick := range h.clients {
		if nick == "" {
			continue
		}
		if _, exists := seen[nick]; !exists {
			seen[nick] = struct{}{}
			users = append(users, nick)
		}
	}
	return users
}

// ActiveUsersDetailed returns connected users with their presence metadata,
// deduplicated by nickname. Users who set "appear offline" are omitted.
func (h *Hub) ActiveUsersDetailed() []presenceUser {
	h.mu.RLock()
	defer h.mu.RUnlock()

	seen := make(map[string]struct{})
	users := []presenceUser{}
	for _, nick := range h.clients {
		if nick == "" {
			continue
		}
		if _, exists := seen[nick]; exists {
			continue
		}
		seen[nick] = struct{}{}

		meta, ok := h.presenceMeta[nick]
		status := meta.Status
		if !ok || status == "" {
			status = "online"
		}
		if status == "offline" {
			continue // appear offline: hidden from the roster
		}
		users = append(users, presenceUser{Nickname: nick, Status: status, ProjectID: meta.ProjectID})
	}
	return users
}

// SetPresenceMeta updates a user's presence metadata and rebroadcasts presence.
func (h *Hub) SetPresenceMeta(nickname, status, projectID string) {
	if nickname == "" {
		return
	}
	h.mu.Lock()
	h.presenceMeta[nickname] = presenceInfo{Status: status, ProjectID: projectID}
	h.mu.Unlock()
	h.broadcastPresence()
}

// broadcastPresence sends a team.presence event with the current active user list.
func (h *Hub) broadcastPresence() {
	h.broadcast <- map[string]any{
		"type": "team.presence",
		"data": map[string]any{"users": h.ActiveUsersDetailed()},
	}
}

// Rename swaps oldNick → newNick on an existing conn and emits team.nickname_changed. Returns (false, nil) if oldNick has no conn.
func (h *Hub) Rename(oldNick, newNick string) (bool, error) {
	h.mu.Lock()
	var oldConn *websocket.Conn
	for c, nick := range h.clients {
		if nick == newNick {
			h.mu.Unlock()
			return false, errNicknameInUse
		}
		if nick == oldNick && oldConn == nil {
			oldConn = c
		}
	}
	if oldConn == nil {
		h.mu.Unlock()
		return false, nil
	}
	h.clients[oldConn] = newNick
	if meta, ok := h.presenceMeta[oldNick]; ok {
		h.presenceMeta[newNick] = meta
		delete(h.presenceMeta, oldNick)
	}
	h.mu.Unlock()

	h.broadcast <- map[string]any{
		"type": "team.nickname_changed",
		"data": map[string]any{
			"oldNickname": oldNick,
			"newNickname": newNick,
		},
	}
	return true, nil
}

// ServeWS upgrades the HTTP connection to WebSocket and registers the client.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	// Extract nickname from query param (set by auth middleware or relay).
	nickname := r.URL.Query().Get("nickname")

	// Reject duplicate nicknames before upgrading.
	if nickname != "" && h.HasNickname(nickname) {
		http.Error(w, `{"error":"nickname already in use"}`, http.StatusConflict)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	// Double-check under write lock to prevent race between HasNickname and registration.
	h.mu.Lock()
	if nickname != "" {
		for _, nick := range h.clients {
			if nick == nickname {
				h.mu.Unlock()
				conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "nickname already in use"))
				conn.Close()
				return
			}
		}
	}
	h.clients[conn] = nickname
	h.mu.Unlock()

	if nickname != "" {
		h.broadcastPresence()

		if h.onConnect != nil {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			h.onConnect(nickname, ip)
		}
	}

	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
		if nickname != "" {
			h.broadcastPresence()
			if h.onDisconnect != nil {
				ip, _, _ := net.SplitHostPort(r.RemoteAddr)
				if ip == "" {
					ip = r.RemoteAddr
				}
				h.onDisconnect(nickname, ip)
			}
		}
		conn.Close()
	}()

	// Drain client messages; disconnect on any error.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
