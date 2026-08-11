package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/proxy"
)

// WebSocket list caps. Payloads are previewed rather than returned whole: a single
// frame can be megabytes, and the reason to list frames is to find the interesting
// one, not to read all of them.
const (
	defaultWSLimit   = 50
	maxWSLimit       = 200
	defaultWSPreview = 120
	maxWSPreview     = 1024
)

type wsListArgs struct {
	Host    string `json:"host"`
	Offset  int    `json:"offset"`
	Limit   int    `json:"limit"`
	Preview int    `json:"preview"`
}

func registerWebSocket(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "websocket.list",
		Class: capability.ClassWebSocket,
		Title: "List captured WebSocket messages",
		Description: "Frames captured from proxied WebSocket connections: connection, direction, opcode, length " +
			"and a text preview. Binary payloads are reported by length only. Read-only — sending a frame is " +
			"done by the operator from the Manipulate tab.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":    {"type":"string","description":"Restrict to connections whose host contains this substring."},
    "offset":  {"type":"integer","minimum":0,"description":"Row offset for paging."},
    "limit":   {"type":"integer","minimum":1,"maximum":200,"description":"Rows to return; default 50."},
    "preview": {"type":"integer","minimum":1,"maximum":1024,"description":"Characters of payload preview per row; default 120."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"limit":30}`),
		MaxOutputBytes: 128 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args wsListArgs) (any, error) {
			if d.WSStore == nil {
				return nil, fmt.Errorf("WebSocket capture is unavailable")
			}
			limit := clampInt(args.Limit, defaultWSLimit, 1, maxWSLimit)
			preview := clampInt(args.Preview, defaultWSPreview, 1, maxWSPreview)

			items, total := d.WSStore.List(proxy.WSMessageFilter{
				Host: args.Host, Offset: args.Offset, Limit: limit,
			})
			return renderWSMessages(items, total, args.Offset, preview), nil
		}),
	})
}

func renderWSMessages(items []*proxy.CapturedWSMessage, total, offset, preview int) string {
	if len(items) == 0 {
		return "(no WebSocket messages captured)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d/%d off=%d\n", len(items), total, offset)

	widths := []int{0, 0, 0, 0, 0}
	rows := make([][]string, 0, len(items))
	for _, m := range items {
		row := []string{
			shortConnID(m.ConnectionID),
			wsDirection(m.Direction),
			wsOpcode(m.Opcode, m.IsText),
			strconv.Itoa(m.PayloadLength),
			m.Host,
			wsPreview(m, preview),
		}
		for i := range widths {
			widths[i] = max(widths[i], len(row[i]))
		}
		rows = append(rows, row)
	}

	b.WriteString(pad("conn", widths[0]) + " " + pad("dir", widths[1]) + " " +
		pad("op", widths[2]) + " " + pad("len", widths[3]) + " " +
		pad("host", widths[4]) + " payload\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s %s %s %s %s | %s\n",
			pad(r[0], widths[0]), pad(r[1], widths[1]), pad(r[2], widths[2]),
			pad(r[3], widths[3]), pad(r[4], widths[4]), r[5])
	}
	return strings.TrimRight(b.String(), "\n")
}

// shortConnID trims the connection id to enough characters to group frames by
// connection, which is all a reader needs it for.
func shortConnID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return orDefault(id, "-")
}

func wsDirection(dir string) string {
	if dir == "client_to_server" {
		return "c->s"
	}
	return "s->c"
}

func wsOpcode(op byte, isText bool) string {
	switch op {
	case 0x1:
		return "text"
	case 0x2:
		return "bin"
	case 0x8:
		return "close"
	case 0x9:
		return "ping"
	case 0xA:
		return "pong"
	}
	if isText {
		return "text"
	}
	return "0x" + strconv.FormatUint(uint64(op), 16)
}

// wsPreview renders a frame payload on one line. A binary payload is base64 in the
// store, which is noise to a reader, so it is reported by length only.
func wsPreview(m *proxy.CapturedWSMessage, n int) string {
	if !m.IsText {
		return "<binary>"
	}
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 {
			return -1
		}
		return r
	}, m.Payload)
	return trunc(strings.TrimSpace(s), n)
}
