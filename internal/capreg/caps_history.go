package capreg

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/httptools"
)

// Shared schema fragments. These are hand-written rather than generated from
// struct tags: a reflection-based schema walker is a few hundred lines of exactly
// the infrastructure this repo declines to carry, and it cannot emit the
// description strings — which are the whole point, because they are the contract
// text a model reads before deciding how to call the tool. There are thirteen
// capabilities, not two hundred. Each ArgsExample must be a valid instance of its
// schema and must decode through the handler's own decoder — keeping that pairing
// true by hand is what stops the schema and the Go struct drifting apart.
const historyFilterProps = `
    "host":         {"type":"string","description":"Exact host to filter to, e.g. api.example.com."},
    "method":       {"type":"string","description":"Comma-separated methods, OR'd: \"GET,POST\"."},
    "status":       {"type":"string","description":"Status expression OR'ing classes, exact codes and ranges: \"4xx,5xx,403,500-599\". \"none\" matches requests with no captured response."},
    "search":       {"type":"string","description":"Case-insensitive substring of the URL."},
    "contentType":  {"type":"string","description":"Content-type keywords, comma-separated: html, json, js, xml, css, image, font, text."},
    "exclude":      {"type":"string","description":"Comma-separated file extensions to exclude, e.g. \".css,.png\"."},
    "extMode":      {"type":"string","enum":["exclude","include"],"description":"Whether \"exclude\" lists extensions to drop (default) or to keep."},
    "scopeOnly":    {"type":"boolean","description":"Restrict to requests matching Joro's configured scope."}`

func registerHistory(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:    "history.list",
		Class: capability.ClassHistory,
		Title: "List captured requests",
		Description: "List proxied requests as a compact table: seq, method, status, length, duration, " +
			"content-type keyword and path. Requests are addressed everywhere else by their integer seq. " +
			"Returns no request or response bodies — use http_read, http_search or http_fingerprint for those. " +
			"The content filter greps raw request and response bytes inside the store, so it is a cheap " +
			"corpus-wide search that never copies a body. It matches the bytes as captured, including header " +
			"values that http_read and http_search mask, so it reports whether a string is present without " +
			"returning it.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{` + historyFilterProps + `,
    "content":      {"type":"string","description":"Match against raw request+response bytes. Note these are the bytes as captured, so a compressed response will not match a plaintext pattern."},
    "contentRegex": {"type":"boolean","description":"Treat content as a regular expression (RE2: no lookahead or backreferences)."},
    "contentMode":  {"type":"string","enum":["include","exclude"],"description":"Whether content selects (default) or rejects matching requests."},
    "offset":       {"type":"integer","minimum":0,"description":"Row offset for paging."},
    "limit":        {"type":"integer","minimum":1,"maximum":200,"description":"Rows to return; default 50, max 200."},
    "fields":       {"type":"string","description":"Optional extra columns: \"+ts\" for a timestamp, \"+proto\" for the HTTP version. Omitted by default because they are rarely used for reasoning and cost tokens on every row."}
  },
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"status":"5xx","limit":20}`),
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args httptools.HistoryArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			return httptools.ListHistory(d.Store, d.Scope, args), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "history.stats",
		Class: capability.ClassHistory,
		Title: "Summarize captured traffic",
		Description: "Counts of captured requests by status class and by host. The cheapest way to orient " +
			"at the start of a session: one call instead of listing history to infer the same shape.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":      {"type":"string","description":"Restrict the summary to one host."},
    "method":    {"type":"string","description":"Comma-separated methods."},
    "status":    {"type":"string","description":"Status expression, e.g. \"4xx,5xx\"."},
    "scopeOnly": {"type":"boolean","description":"Restrict to requests matching Joro's configured scope."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"scopeOnly":true}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args httptools.HistoryArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			return httptools.HistoryStats(d.Store, d.Scope, args), nil
		}),
	})
}
