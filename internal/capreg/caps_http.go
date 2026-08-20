package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/httptools"
)

// editSchema is shared by http_resend and http_batch.
//
// Edits are structural so a client never has to ship a whole request back. That
// saves hundreds to thousands of tokens per attempt, but the stronger reason is
// correctness: a model retyping raw bytes will eventually corrupt one, and a
// mangled Cookie turns a negative result into a false negative — the worst outcome
// in a security test, because it reads as "not vulnerable".
const editSchema = `{
  "type":"object",
  "properties":{
    "op":    {"type":"string","enum":["setHeader","addHeader","removeHeader","setMethod","setPath","setQuery","removeQuery","setRequestTarget","replaceInBody","setBody"],"description":"The edit to apply. Edits run in array order."},
    "name":  {"type":"string","description":"Header name (setHeader/addHeader/removeHeader) or query parameter name (setQuery/removeQuery)."},
    "value": {"type":"string","description":"New value. For setBody, the whole body."},
    "find":  {"type":"string","description":"replaceInBody only: the text or pattern to replace."},
    "regex": {"type":"boolean","description":"replaceInBody only: treat find as an RE2 regular expression."},
    "all":   {"type":"boolean","description":"replaceInBody only: replace every occurrence."},
    "count": {"type":"integer","description":"replaceInBody only: replace at most this many occurrences."}
  },
  "required":["op"],
  "additionalProperties":false
}`

func registerHTTP(r *capability.Registry, d Deps) {
	sendDeps := httptools.SendDeps{ProxyAddr: d.ProxyAddr, CA: d.CA, Store: d.Store}
	// The jar is per-principal, so TokenID is filled in per invocation.
	resendDeps := func(p capability.Principal) httptools.ResendDeps {
		return httptools.ResendDeps{
			Send: sendDeps, Store: d.Store,
			Contexts: d.Contexts, TokenID: p.TokenID,
		}
	}

	r.MustRegister(capability.Capability{
		ID:    "http.fingerprint",
		Class: capability.ClassHTTP,
		Title: "Fingerprint captured responses",
		Description: "Compact fingerprints for one or more captured responses: status, decompressed length, " +
			"duration, an exact body hash (bhash) and a structural hash (shash) that ignores volatile values " +
			"such as CSRF tokens, timestamps, UUIDs and nonces. Two responses that differ only in a nonce share " +
			"an shash and differ in bhash — which is how to tell 'same page' from 'genuinely different' without " +
			"reading either body.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "ref":    {"type":"integer","description":"A captured request's seq, as shown by history_list."},
    "refs":   {"type":"array","items":{"type":"integer"},"maxItems":50,"description":"Several seqs, rendered as a comparison table. Max 50."},
    "fields": {"type":"string","description":"\"+fullhash\" to include the full SHA-256 rather than its 8-hex prefix."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"refs":[1204,1209,1213]}`),
		MaxOutputBytes: 64 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args httptools.FingerprintArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			return httptools.FingerprintRefs(d.Store, args)
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "http.read",
		Class: capability.ClassHTTP,
		Title: "Read a byte range of a captured request or response",
		Description: "Read a window of a captured request or response. Returns at most 16 KB per call and " +
			"reports totalLength, offset, returned and truncated so you can page. A negative offset reads " +
			"from the end, which is the cheapest way to see the bottom of an error page. Compressed bodies " +
			"are decompressed by default; section \"raw\" is always byte-exact. Binary data is returned as a " +
			"hex dump when small, base64 when not. Unless this token has credential visibility, the values " +
			"of Authorization, Cookie, Set-Cookie and similar headers are overwritten with '*' — the header " +
			"is present, and offsets are unaffected, but the value is withheld, and what is withheld inside " +
			"the bytes returned is named, and only that. " +
			"As a tool this renders one metadata line, then the bytes, then any notes: the bytes begin after " +
			"the first newline and nothing is ever inserted ahead of them. From the SDK it is an object — " +
			"{ref, part, section, encoding, totalLength, offset, returned, truncated, text, redacted[], " +
			"decoded} — where text is exactly the bytes, with no metadata and no notes, so a script reads " +
			"fields instead of parsing.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "ref":      {"type":"integer","description":"A captured request's seq."},
    "part":     {"type":"string","enum":["req","resp"],"description":"Which half to read; default resp."},
    "section":  {"type":"string","enum":["headers","body","raw"],"description":"Which section; default body. \"raw\" is the whole dump with no decoding."},
    "offset":   {"type":"integer","description":"Byte offset within the section. Negative reads from the end."},
    "length":   {"type":"integer","minimum":1,"maximum":16384,"description":"Bytes to return; default 2048, max 16384."},
    "decode":   {"type":"boolean","description":"Decompress gzip/deflate before slicing; default true. Forced off for section \"raw\"."},
    "encoding": {"type":"string","enum":["auto","text","hex","base64"],"description":"How to render the bytes; default auto."}
  },
  "required":["ref"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"ref":1204,"offset":-2048}`),
		MaxOutputBytes: 128 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args httptools.ReadArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			item := d.Store.GetBySeq(args.Ref)
			if item == nil {
				return nil, fmt.Errorf("no captured request with seq %d", args.Ref)
			}
			return httptools.ReadRange(item.ReqRaw, item.RespRaw, args, !p.AllowCredentials)
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "http.search",
		Class: capability.ClassHTTP,
		Title: "Search captured traffic",
		Description: "Find a string or regex across captured traffic and return match offsets with surrounding " +
			"context, without returning any bodies. With ref set it searches one request; without it, it " +
			"searches a filtered corpus. Matching is against the bytes as captured, so a compressed response " +
			"will not match a plaintext pattern unless deep is set. Matching is case-insensitive by default. " +
			"Unless this token has credential visibility, sensitive header values are masked before matching, " +
			"so a pattern will not match inside one.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "pattern":       {"type":"string","description":"The string or RE2 pattern to find."},
    "regex":         {"type":"boolean","description":"Treat pattern as a regular expression."},
    "ref":           {"type":"integer","description":"Search only this captured request. Omit to search the corpus."},
    "part":          {"type":"string","enum":["req","resp","both"],"description":"Which half to search; default resp."},` +
			historyFilterProps + `,
    "maxRequests":   {"type":"integer","minimum":1,"maximum":200,"description":"Corpus mode: requests to scan; default 50."},
    "maxMatches":    {"type":"integer","minimum":1,"maximum":40,"description":"Matches per request; default 3 in corpus mode, 20 for a single request."},
    "context":       {"type":"integer","minimum":1,"maximum":200,"description":"Bytes of context each side of a match; default 60."},
    "caseSensitive": {"type":"boolean","description":"Narrow to case-sensitive matching."},
    "deep":          {"type":"boolean","description":"Decompress bodies before searching. Slower, and offsets then refer to the decoded document."}
  },
  "required":["pattern"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"pattern":"X-Debug-Token"}`),
		MaxOutputBytes: 128 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args httptools.SearchArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			return httptools.SearchCorpus(httptools.SearchDeps{
				Store:           d.Store,
				Scope:           d.Scope,
				MaskCredentials: !p.AllowCredentials,
			}, args)
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "http.diff",
		Class: capability.ClassHTTP,
		Title: "Diff two captured responses",
		Description: "Structured diff of two captured responses. Status, headers and body are reported " +
			"separately, so a header change is not buried under a body diff. The body diff is line-level with " +
			"unified hunks. Volatile values are ignored by default so nonces and timestamps do not dominate. " +
			"Values of Set-Cookie, Authorization and similar headers are never shown, only their presence.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "a":              {"type":"integer","description":"Seq of the first captured request."},
    "b":              {"type":"integer","description":"Seq of the second."},
    "part":           {"type":"string","enum":["req","resp"],"description":"Which half to compare; default resp."},
    "ignoreVolatile": {"type":"boolean","description":"Normalize volatile values before comparing; default true. Lines are always displayed as they really are."},
    "maxHunks":       {"type":"integer","minimum":1,"maximum":40,"description":"Hunks to show; default 12."},
    "contextLines":   {"type":"integer","minimum":0,"maximum":5,"description":"Context lines around each hunk; default 2."}
  },
  "required":["a","b"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"a":1204,"b":1209}`),
		MaxOutputBytes: 128 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args httptools.DiffArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			a := d.Store.GetBySeq(args.A)
			if a == nil {
				return nil, fmt.Errorf("no captured request with seq %d", args.A)
			}
			b := d.Store.GetBySeq(args.B)
			if b == nil {
				return nil, fmt.Errorf("no captured request with seq %d", args.B)
			}
			aRaw, bRaw := a.RespRaw, b.RespRaw
			if args.Part == "req" {
				aRaw, bRaw = a.ReqRaw, b.ReqRaw
			}
			return httptools.DiffMessages(aRaw, bRaw, args.A, args.B, args), nil
		}),
	})

	// ---- Sends. Everything below emits traffic, so it carries a Target extractor
	// and the registry runs the scope guard before the handler.

	r.MustRegister(capability.Capability{
		ID:           "http.resend",
		Class:        capability.ClassHTTP,
		Title:        "Edit and resend a captured request",
		SendsTraffic: true,
		Description: "Apply structural edits to a captured request and send it through Joro's proxy, so the " +
			"result is captured into history like any other request and gets its own seq. Returns a " +
			"fingerprint, not a body — read the result with http_read or compare it with http_diff. " +
			"Redirects are never followed: read the Location header and issue a second call, which is " +
			"checked against scope in its own right. Match & Replace and Custom Data rules apply, so the " +
			"bytes on the wire may differ from what you specify. Session cookies held for this token are " +
			"applied unless the request already carries that cookie or your edits touch the Cookie header, " +
			"and any Set-Cookie in the response is recorded for later sends.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "ref":                 {"type":"integer","description":"Seq of the captured request to base this on."},
    "edits":               {"type":"array","items":` + editSchema + `,"description":"Structural edits, applied in order."},
    "scheme":              {"type":"string","enum":["http","https"],"description":"Override the scheme; defaults to the captured request's."},
    "host":                {"type":"string","description":"Override the host; defaults to the captured request's. Must pass this token's scope and host whitelist."},
    "updateContentLength": {"type":"boolean","description":"Recalculate Content-Length after editing; default true."},
    "timeoutMs":           {"type":"integer","minimum":1000,"maximum":60000,"description":"Per-request timeout; default 15000."},
    "useContext":          {"type":"boolean","description":"Apply and record this token's session cookies; default true. Set false to send exactly what you specified, e.g. when testing unauthenticated access."}
  },
  "required":["ref"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"ref":1204,"edits":[{"op":"setHeader","name":"X-Forwarded-For","value":"127.0.0.1"}]}`),
		MaxOutputBytes: 32 << 10,
		Timeout:        70 * time.Second, // over the max per-request timeout, so the tool times out first
		Target: capability.TypedTarget(func(args httptools.ResendArgs) (capability.Target, error) {
			return resolveTarget(d, args.Ref, args.Scheme, args.Host, args.Edits)
		}),
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args httptools.ResendArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			return httptools.Resend(ctx, resendDeps(p), args)
		}),
	})

	r.MustRegister(capability.Capability{
		ID:           "http.batch",
		Class:        capability.ClassHTTP,
		Title:        "Send a capped batch of request variants",
		SendsTraffic: true,
		Description: "Send up to 50 labelled variants of one captured request through Joro's proxy and return " +
			"one comparison table. Rows sharing a structural hash are the same response; the tool computes " +
			"which rows are outliers and names them, so the answer is in the summary rather than something " +
			"you have to infer. For larger runs, use Joro's fuzzer from the Fuzz tab instead.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "ref":      {"type":"integer","description":"Seq of the captured request to base every variant on."},
    "variants": {
      "type":"array","minItems":1,"maxItems":50,
      "items":{
        "type":"object",
        "properties":{
          "label":{"type":"string","maxLength":24,"description":"Short label; this is how you correlate a result row back to your edit."},
          "edits":{"type":"array","items":` + editSchema + `}
        },
        "required":["label"],
        "additionalProperties":false
      }
    },
    "scheme":        {"type":"string","enum":["http","https"]},
    "host":          {"type":"string","description":"Override the host. Must pass this token's scope and host whitelist."},
    "concurrency":   {"type":"integer","minimum":1,"maximum":10,"description":"Parallel requests; default 4."},
    "ratePerSec":    {"type":"number","minimum":0,"maximum":50,"description":"Requests per second across all workers; 0 means unlimited."},
    "timeoutMs":     {"type":"integer","minimum":1000,"maximum":60000,"description":"Per-request timeout; default 10000."},
    "totalBudgetMs": {"type":"integer","minimum":1000,"maximum":120000,"description":"Wall-clock budget for the whole batch; default 60000."},
    "useContext":    {"type":"boolean","description":"Apply this token's session cookies to every variant; default true. Set-Cookie from a batch is never recorded, so all variants start from the same session."}
  },
  "required":["ref","variants"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"ref":1204,"variants":[{"label":"baseline"},` +
			`{"label":"xff-lo","edits":[{"op":"setHeader","name":"X-Forwarded-For","value":"127.0.0.1"}]}]}`),
		MaxOutputBytes: 64 << 10,
		Timeout:        130 * time.Second, // over the max total budget, so the tool times out first
		Target: capability.TypedTarget(func(args httptools.BatchArgs) (capability.Target, error) {
			return resolveTarget(d, args.Ref, args.Scheme, args.Host, nil)
		}),
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args httptools.BatchArgs) (any, error) {
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			return httptools.Batch(ctx, resendDeps(p), args)
		}),
	})
}

// resolveTarget derives the destination a send will dial, for the scope guard.
//
// It applies the edits first, so the guard checks the method and path that will
// actually be sent rather than the ones that were captured. An agent editing the
// path into a scope-excluded prefix has to be caught here, before any bytes leave.
//
// A batch checks only the base request's target: every variant shares one host,
// and the per-variant edits cannot change it because scheme and host are batch-level
// arguments. Path edits within a batch are not individually guarded, which is a
// gap worth knowing about — it is bounded by the host check, which is the control
// that matters for staying inside an engagement.
func resolveTarget(d Deps, ref int, scheme, host string, edits []httptools.Edit) (capability.Target, error) {
	if d.Store == nil {
		return capability.Target{}, fmt.Errorf("capture store is unavailable")
	}
	_, h, method, path, err := httptools.TargetOf(d.Store, ref, scheme, host, edits)
	if err != nil {
		return capability.Target{}, err
	}
	return capability.Target{Host: h, Method: method, Path: path}, nil
}
