package capreg

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/event"
	"github.com/BishopFox/joro/internal/proxy"
)

// Rendering helpers for the context capabilities. They follow the same encoding
// rule as internal/httptools: uniform rows become a fixed-width table, because
// repeated JSON keys are over half the token cost of a row.

func renderSitemap(hosts []proxy.SitemapHost, maxPaths int) string {
	if maxPaths <= 0 {
		maxPaths = 200
	}
	if len(hosts) == 0 {
		return "(no requests captured yet)"
	}
	var b strings.Builder
	for _, h := range hosts {
		fmt.Fprintf(&b, "%s  (%d requests, %d paths)\n", h.Origin, h.Count, len(h.Endpoints))
		for i, ep := range h.Endpoints {
			if i >= maxPaths {
				fmt.Fprintf(&b, "  [%d more paths; filter with host=]\n", len(h.Endpoints)-maxPaths)
				break
			}
			line := "  " + strings.Join(ep.Methods, ",") + " " + ep.Path
			if len(ep.Params) > 0 {
				line += " ?" + strings.Join(ep.Params, ",")
			}
			b.WriteString(line + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func renderFindings(items []detect.Finding, total, offset int) string {
	if len(items) == 0 {
		return "(no findings matched)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d/%d off=%d\n", len(items), total, offset)

	widths := []int{0, 0, 0, 0}
	rows := make([][]string, 0, len(items))
	for _, f := range items {
		fp := ""
		if f.FalsePositive {
			fp = " [FP]"
		}
		row := []string{
			string(f.Severity),
			f.ID,
			strconv.Itoa(f.Count),
			f.Host,
			f.RuleName + fp,
			trunc(f.Evidence, 60),
		}
		for i := range widths {
			widths[i] = max(widths[i], len(row[i]))
		}
		rows = append(rows, row)
	}

	b.WriteString(pad("sev", widths[0]) + " " + pad("id", widths[1]) + " " +
		pad("n", widths[2]) + " " + pad("host", widths[3]) + " rule / evidence\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s %s %s %s %s | %s\n",
			pad(r[0], widths[0]), pad(r[1], widths[1]), pad(r[2], widths[2]),
			pad(r[3], widths[3]), r[4], r[5])
	}
	return strings.TrimRight(b.String(), "\n")
}

func pad(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func clampInt(v, def, lo, hi int) int {
	if v <= 0 {
		v = def
	}
	return min(max(v, lo), hi)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// joinOr renders a string list as CSV, or def when it is empty — the shape the rule
// tables use for "all methods" and similar.
func joinOr(parts []string, def string) string {
	if len(parts) == 0 {
		return def
	}
	return strings.Join(parts, ",")
}

// broadcast pushes a WS event from a mutating capability, so an agent editing the
// operator's configuration is visible while it happens rather than on next reload.
//
// The send is non-blocking. Some REST call sites send to this channel blocking, but a
// capability handler runs under a 30s timeout that a full hub channel would consume,
// and a dropped notification is a stale panel while a stalled handler is a failed
// tool call. This follows the detect.finding precedent, which is droppable for the
// same reason. Only event types the frontend already handles are worth sending.
func broadcast(d Deps, eventType string, data any) {
	if d.Broadcast == nil {
		return
	}
	select {
	case d.Broadcast <- event.WSEvent{Type: eventType, Data: data}:
	default:
	}
}
