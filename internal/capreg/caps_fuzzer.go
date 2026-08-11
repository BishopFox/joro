package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/fuzzer"
	"github.com/BishopFox/joro/internal/httptools"
)

// Caps on an agent-started campaign, well below what the Fuzz tab allows.
//
// The wordlist bound is what bounds the request count: with one wordlist the
// campaign is one request per entry, so there is no cartesian product to guard
// against. Anything larger belongs in the UI, where the operator is watching and
// can upload a real wordlist rather than shipping one through a tool call.
const (
	maxFuzzWords     = 500
	maxFuzzWordBytes = 64 << 10
	maxFuzzThreads   = 10
	defaultFuzzConc  = 4

	defaultFuzzResults = 50
	maxFuzzResults     = 200
)

type fuzzStartArgs struct {
	Ref        int              `json:"ref"`
	Edits      []httptools.Edit `json:"edits"`
	Wordlist   []string         `json:"wordlist"`
	Scheme     string           `json:"scheme"`
	Host       string           `json:"host"`
	Threads    int              `json:"threads"`
	RatePerSec float64          `json:"ratePerSec"`
}

type fuzzCampaignArgs struct {
	ID string `json:"id"`
}

type fuzzResultsArgs struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}

func registerFuzzer(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:           "fuzzer.start",
		Class:        capability.ClassFuzzer,
		Title:        "Start a fuzzing campaign",
		SendsTraffic: true,
		Description: "Run a wordlist against one position in a captured request. Insert the marker FUZZ with an " +
			"edit — setPath, setQuery, setHeader or replaceInBody — and every wordlist entry is substituted for " +
			"it in turn. Returns a campaign id immediately; poll fuzzer_status and read fuzzer_results. " +
			"Wordlists are capped at 500 entries, so this is for a focused sweep; larger runs belong in the " +
			"Fuzz tab. Unlike http_resend, fuzzer traffic does not pass through the proxy, so results are not " +
			"captured into history and have no seq — the metrics returned here are the whole record.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "ref":        {"type":"integer","description":"Seq of the captured request to use as the template."},
    "edits":      {"type":"array","items":` + editSchema + `,"description":"Edits that must introduce the marker FUZZ, e.g. {\"op\":\"setQuery\",\"name\":\"id\",\"value\":\"FUZZ\"}."},
    "wordlist":   {"type":"array","items":{"type":"string"},"minItems":1,"maxItems":500,"description":"Payloads substituted for FUZZ, one request each. Max 500 entries, 64 KB total."},
    "scheme":     {"type":"string","enum":["http","https"],"description":"Override the scheme; defaults to the captured request's."},
    "host":       {"type":"string","description":"Override the host. Must pass this token's scope and host whitelist."},
    "threads":    {"type":"integer","minimum":1,"maximum":10,"description":"Concurrent requests; default 4."},
    "ratePerSec": {"type":"number","minimum":0,"maximum":50,"description":"Requests per second across all threads; 0 means unlimited."}
  },
  "required":["ref","wordlist"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"ref":1204,"edits":[{"op":"setPath","value":"/admin/FUZZ"}],` +
			`"wordlist":["users","config","backup"],"ratePerSec":10}`),
		MaxOutputBytes: 8 << 10,
		Target: capability.TypedTarget(func(args fuzzStartArgs) (capability.Target, error) {
			return resolveTarget(d, args.Ref, args.Scheme, args.Host, args.Edits)
		}),
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args fuzzStartArgs) (any, error) {
			if d.Fuzzer == nil || d.Transport == nil {
				return nil, fmt.Errorf("the fuzzer is unavailable")
			}
			if d.Store == nil {
				return nil, fmt.Errorf("capture store is unavailable")
			}
			item := d.Store.GetBySeq(args.Ref)
			if item == nil {
				return nil, fmt.Errorf("no captured request with seq %d", args.Ref)
			}
			if len(item.ReqRaw) == 0 {
				return nil, fmt.Errorf("request %d has no captured bytes to fuzz", args.Ref)
			}

			words, err := checkWordlist(args.Wordlist)
			if err != nil {
				return nil, err
			}

			raw, err := httptools.ApplyEdits(item.ReqRaw, args.Edits)
			if err != nil {
				return nil, err
			}
			positions := fuzzer.DetectPositions(raw)
			if len(positions) == 0 {
				return nil, fmt.Errorf("the request contains no FUZZ marker after your edits. Add one with an " +
					`edit, e.g. {"op":"setQuery","name":"id","value":"FUZZ"} or ` +
					`{"op":"replaceInBody","find":"8291","value":"FUZZ"}`)
			}

			scheme, host, _, _, err := httptools.TargetOf(d.Store, args.Ref, args.Scheme, args.Host, args.Edits)
			if err != nil {
				return nil, err
			}

			cfg := fuzzer.Config{
				RawRequest: raw,
				Scheme:     scheme,
				Host:       host,
				Wordlist:   words,
				Positions:  positions,
				// One wordlist across however many markers the edits introduced, so a
				// repeated id is substituted consistently rather than needing a map.
				AttackMode:          fuzzer.AttackSpray,
				Threads:             clampInt(args.Threads, defaultFuzzConc, 1, maxFuzzThreads),
				RateLimit:           min(max(args.RatePerSec, 0), 50),
				UpdateContentLength: true,
			}
			if len(positions) > 1 {
				cfg.Wordlists = map[string][]string{positions[0]: words}
			}

			// A campaign outlives the invocation that started it, so it runs under the
			// server-lifetime context rather than this call's 30s timeout.
			bg := context.Background()
			if d.BgCtx != nil {
				bg = d.BgCtx()
			}
			runCtx, cancel := context.WithCancel(bg)
			campaign := fuzzer.NewCampaign(cfg, cancel)
			d.Fuzzer.Add(campaign)
			go fuzzer.Run(runCtx, campaign, d.Transport, d.Broadcast)

			capability.RecordChange(ctx, "start fuzz campaign %s on %s (%d requests, %s)",
				campaign.ID, host, campaign.Total, strings.Join(positions, ","))
			return fmt.Sprintf("started campaign id=%s total=%d positions=%s target=%s://%s\n"+
				"poll: fuzzer_status{id:%q}   read: fuzzer_results{id:%q}",
				campaign.ID, campaign.Total, strings.Join(positions, ","), scheme, host,
				campaign.ID, campaign.ID), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "fuzzer.status",
		Class: capability.ClassFuzzer,
		Title: "Check fuzzing campaign progress",
		Description: "Progress of one campaign, or a list of them when id is omitted: status, requests completed " +
			"out of total, and error count. Poll this rather than fuzzer_results while a campaign is running.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id": {"type":"string","description":"Campaign id. Omit to list every campaign."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 16 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args fuzzCampaignArgs) (any, error) {
			if d.Fuzzer == nil {
				return nil, fmt.Errorf("the fuzzer is unavailable")
			}
			if strings.TrimSpace(args.ID) == "" {
				campaigns := d.Fuzzer.List()
				if len(campaigns) == 0 {
					return "(no campaigns)", nil
				}
				var b strings.Builder
				for _, c := range campaigns {
					fmt.Fprintf(&b, "%s %s %d/%d errors=%d\n",
						c.ID, c.Status, c.Completed, c.Total, c.Errors)
				}
				return strings.TrimRight(b.String(), "\n"), nil
			}
			c := d.Fuzzer.Get(args.ID)
			if c == nil {
				return nil, fmt.Errorf("no campaign with id %s", args.ID)
			}
			return fmt.Sprintf("id=%s status=%s completed=%d/%d errors=%d",
				c.ID, c.Status, c.Completed, c.Total, c.Errors), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "fuzzer.results",
		Class: capability.ClassFuzzer,
		Title: "Read fuzzing campaign results",
		Description: "Results for a campaign as a comparison table: payload, status, size, words, lines and " +
			"duration. Rows are grouped by status and size in the summary, so the outliers are named rather " +
			"than left for you to spot. Response bodies are not stored by the fuzzer; to inspect one, resend " +
			"that payload with http_resend, which does capture it.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id":     {"type":"string","description":"Campaign id."},
    "status": {"type":"string","description":"Keep only these status codes, comma-separated, e.g. \"200,403\"."},
    "offset": {"type":"integer","minimum":0,"description":"Row offset for paging."},
    "limit":  {"type":"integer","minimum":1,"maximum":200,"description":"Rows to return; default 50."}
  },
  "required":["id"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"id":"6f1c...","status":"200,403"}`),
		MaxOutputBytes: 128 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args fuzzResultsArgs) (any, error) {
			if d.Fuzzer == nil {
				return nil, fmt.Errorf("the fuzzer is unavailable")
			}
			c := d.Fuzzer.Get(args.ID)
			if c == nil {
				return nil, fmt.Errorf("no campaign with id %s", args.ID)
			}
			limit := clampInt(args.Limit, defaultFuzzResults, 1, maxFuzzResults)
			return renderFuzzResults(c, keepStatuses(args.Status), args.Offset, limit), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "fuzzer.stop",
		Class:    capability.ClassFuzzer,
		Title:    "Stop a fuzzing campaign",
		Mutating: true,
		Description: "Cancel a running campaign. Results already collected are kept and stay readable with " +
			"fuzzer_results.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id": {"type":"string","description":"Campaign id."}
  },
  "required":["id"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"id":"6f1c..."}`),
		MaxOutputBytes: 4 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args fuzzCampaignArgs) (any, error) {
			if d.Fuzzer == nil {
				return nil, fmt.Errorf("the fuzzer is unavailable")
			}
			c := d.Fuzzer.Get(args.ID)
			if c == nil {
				return nil, fmt.Errorf("no campaign with id %s", args.ID)
			}
			if c.Status != fuzzer.StatusRunning {
				return fmt.Sprintf("campaign %s is already %s", c.ID, c.Status), nil
			}
			c.Cancel()
			capability.RecordChange(ctx, "stop fuzz campaign %s after %d/%d", c.ID, c.Completed, c.Total)
			return fmt.Sprintf("stopping campaign %s at %d/%d", c.ID, c.Completed, c.Total), nil
		}),
	})
}

// checkWordlist normalizes and bounds an inline wordlist.
func checkWordlist(words []string) ([]string, error) {
	out := make([]string, 0, len(words))
	total := 0
	for _, w := range words {
		if w == "" {
			continue
		}
		total += len(w)
		out = append(out, w)
	}
	switch {
	case len(out) == 0:
		return nil, fmt.Errorf("wordlist is required and must contain at least one non-empty entry")
	case len(out) > maxFuzzWords:
		return nil, fmt.Errorf("wordlist has %d entries, over the %d limit for an automation campaign; "+
			"narrow it, or upload the full list and run it from the Fuzz tab", len(out), maxFuzzWords)
	case total > maxFuzzWordBytes:
		return nil, fmt.Errorf("wordlist is %d bytes, over the %d byte limit", total, maxFuzzWordBytes)
	}
	return out, nil
}

// keepStatuses parses a comma-separated status list. Nil means keep everything.
func keepStatuses(s string) map[int]bool {
	parts := splitCSV(s)
	if len(parts) == 0 {
		return nil
	}
	keep := make(map[int]bool, len(parts))
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			keep[n] = true
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return keep
}

func renderFuzzResults(c *fuzzer.Campaign, keep map[int]bool, offset, limit int) string {
	all := c.Results()

	rows := make([]fuzzer.Result, 0, len(all))
	for _, r := range all {
		if keep == nil || keep[r.StatusCode] {
			rows = append(rows, r)
		}
	}
	total := len(rows)
	if offset < total {
		end := min(offset+limit, total)
		rows = rows[offset:end]
	} else {
		rows = nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "campaign=%s status=%s completed=%d/%d errors=%d  n=%d/%d off=%d\n",
		c.ID, c.Status, c.Completed, c.Total, c.Errors, len(rows), total, offset)
	if summary := fuzzGroupSummary(all); summary != "" {
		b.WriteString(summary + "\n")
	}
	if len(rows) == 0 {
		b.WriteString("(no results yet)")
		return b.String()
	}

	widths := []int{0, 0, 0, 0, 0}
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		payload := r.Payload
		if payload == "" && len(r.Payloads) > 0 {
			payload = joinPayloads(r.Payloads)
		}
		row := []string{
			trunc(payload, 40),
			statusOrErr(r),
			strconv.Itoa(r.Size),
			strconv.Itoa(r.Words),
			strconv.Itoa(r.Lines),
			strconv.FormatInt(r.DurationMs, 10),
		}
		for i := range widths {
			widths[i] = max(widths[i], len(row[i]))
		}
		cells = append(cells, row)
	}

	b.WriteString(pad("payload", widths[0]) + " " + pad("status", widths[1]) + " " +
		pad("len", widths[2]) + " " + pad("words", widths[3]) + " " +
		pad("lines", widths[4]) + " ms\n")
	for _, r := range cells {
		fmt.Fprintf(&b, "%s %s %s %s %s %s\n",
			pad(r[0], widths[0]), pad(r[1], widths[1]), pad(r[2], widths[2]),
			pad(r[3], widths[3]), pad(r[4], widths[4]), r[5])
	}
	return strings.TrimRight(b.String(), "\n")
}

// fuzzGroupSummary names the shape of the whole result set, so the answer does not
// have to be inferred from the rows. The dominant status+size group is the
// uninteresting baseline; everything else is worth reading.
func fuzzGroupSummary(all []fuzzer.Result) string {
	if len(all) == 0 {
		return ""
	}
	type key struct {
		status, size int
	}
	counts := map[key]int{}
	for _, r := range all {
		if r.Error == "" {
			counts[key{r.StatusCode, r.Size}]++
		}
	}
	if len(counts) <= 1 {
		return ""
	}
	groups := make([]key, 0, len(counts))
	for k := range counts {
		groups = append(groups, k)
	}
	sort.Slice(groups, func(i, j int) bool {
		if counts[groups[i]] != counts[groups[j]] {
			return counts[groups[i]] > counts[groups[j]]
		}
		return groups[i].status < groups[j].status
	})

	parts := make([]string, 0, len(groups))
	for i, g := range groups {
		if i >= 6 {
			parts = append(parts, fmt.Sprintf("+%d more groups", len(groups)-i))
			break
		}
		label := fmt.Sprintf("%d/%dB x%d", g.status, g.size, counts[g])
		if i == 0 {
			label += " (baseline)"
		}
		parts = append(parts, label)
	}
	return "groups: " + strings.Join(parts, "  ")
}

func statusOrErr(r fuzzer.Result) string {
	if r.Error != "" {
		return "err"
	}
	return strconv.Itoa(r.StatusCode)
}

func joinPayloads(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, m[k])
	}
	return strings.Join(parts, "|")
}
