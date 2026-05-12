package event

// WSEvent is a WebSocket event broadcast to all connected clients.
type WSEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}
