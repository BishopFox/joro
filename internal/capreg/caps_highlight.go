package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
)

// highlightColors mirrors HIGHLIGHT_COLORS in web/src/pages/History.tsx, which also
// carries each colour's swatch and row background and stays the frontend's source.
// Keep the two in sync.
var highlightColors = []string{
	"red", "orange", "yellow", "green", "cyan", "blue", "purple", "pink", "gray",
}

type highlightArgs struct {
	Seq   int    `json:"seq" alias:"ref"`
	Color string `json:"color"`
}

func registerHighlight(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:       "history.highlight",
		Class:    capability.ClassHistory,
		Title:    "Colour a request in History",
		Mutating: true,
		Description: "Set or clear the highlight colour on a captured request, so the operator can see which " +
			"rows you flagged while reading their own History. Use it to mark what is worth a second look — it " +
			"annotates, it does not report; findings_create and notes_create are still where a conclusion goes. " +
			"The row updates when the operator next loads History rather than live.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "seq":   {"type":"integer","minimum":1,"description":"The captured request, as returned by history_list."},
    "color": {"type":"string","enum":["red","orange","yellow","green","cyan","blue","purple","pink","gray",""],"description":"Highlight colour. An empty string clears the highlight."}
  },
  "required":["seq","color"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"seq":1842,"color":"red"}`),
		MaxOutputBytes: 4 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args highlightArgs) (any, error) {
			if d.Store == nil || d.SetHighlight == nil {
				return nil, fmt.Errorf("request highlights are unavailable")
			}
			color := strings.ToLower(strings.TrimSpace(args.Color))
			if color != "" && !slices.Contains(highlightColors, color) {
				return nil, fmt.Errorf("colour %q is not one of %s, or \"\" to clear",
					args.Color, strings.Join(highlightColors, ", "))
			}
			item := d.Store.GetBySeq(args.Seq)
			if item == nil {
				return nil, fmt.Errorf("no captured request with seq %d", args.Seq)
			}
			d.SetHighlight(item.ID, color)

			if color == "" {
				capability.RecordChange(ctx, "clear highlight on seq %d (%s)", args.Seq, item.Host)
				return fmt.Sprintf("cleared highlight on seq %d", args.Seq), nil
			}
			capability.RecordChange(ctx, "highlight seq %d %s (%s)", args.Seq, color, item.Host)
			return fmt.Sprintf("highlighted seq %d %s", args.Seq, color), nil
		}),
	})
}
