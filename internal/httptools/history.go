package httptools

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/proxy"
)

// History list caps.
const (
	DefaultHistoryLimit = 50
	MaxHistoryLimit     = 200
	MaxFingerprintRefs  = 50
)

// HistoryArgs maps one-to-one onto proxy.RequestFilter, so this tool adds no
// filtering logic of its own. That is the point of routing through the store:
// RequestFilter.Content and ContentRegex already grep raw request and response
// bytes inside the store's read lock, so a content-filtered listing is a
// corpus-wide grep for free, with no body ever leaving the store.
type HistoryArgs struct {
	Host         string `json:"host"`
	Method       string `json:"method"`
	Status       string `json:"status"`
	Search       string `json:"search"`
	ContentType  string `json:"contentType"`
	Content      string `json:"content"`
	ContentRegex bool   `json:"contentRegex"`
	ContentMode  string `json:"contentMode"`
	Exclude      string `json:"exclude"`
	ExtMode      string `json:"extMode"`
	ScopeOnly    bool   `json:"scopeOnly"`
	Offset       int    `json:"offset"`
	Limit        int    `json:"limit"`
	Fields       string `json:"fields"` // "+ts,+proto"
}

// ListHistory renders a compact table of captured requests.
//
// The handle is Seq, not the hex ID. A sequence number is one or two tokens
// against eight to sixteen for a hex id — over fifty rows that is hundreds of
// tokens of pure identifier — and it is an integer a client can compare ("the 500
// is seven requests after the login") and retype without transposing a character.
func ListHistory(store *proxy.Store, scope *proxy.Scope, args HistoryArgs) string {
	limit := clampInt(args.Limit, DefaultHistoryLimit, 1, MaxHistoryLimit)
	f := proxy.RequestFilter{
		Host:         args.Host,
		Method:       args.Method,
		Status:       args.Status,
		Search:       args.Search,
		ContentType:  args.ContentType,
		Content:      args.Content,
		ContentRegex: args.ContentRegex,
		ContentMode:  args.ContentMode,
		Exclude:      args.Exclude,
		ExtMode:      orDefault(args.ExtMode, "exclude"),
		Offset:       args.Offset,
		Limit:        limit,
	}
	if args.ScopeOnly && scope != nil {
		f.InScopeFunc = scope.InScope
	}

	items, total := store.List(f)
	wantTS := strings.Contains(args.Fields, "+ts")
	wantProto := strings.Contains(args.Fields, "+proto")

	// Elide a host shared by every row into the preamble: about six tokens a row.
	common := commonHost(items)

	cols := []string{"seq", "method", "status", "len", "ms", "ct"}
	if wantProto {
		cols = append(cols, "proto")
	}
	if wantTS {
		cols = append(cols, "ts")
	}
	if common == "" {
		cols = append(cols, "host")
	}
	cols = append(cols, "path")

	t := newTable(cols...)
	t.empty = "(no requests matched)"
	// Only diagnose a genuinely empty match. A page emptied by an offset past the
	// end is already explained by the n=0/<total> off=<n> preamble, and blaming
	// the filters there would send the caller after the wrong thing.
	if total == 0 {
		t.empty = emptyHint(store, args.Host)
	}
	note := fmt.Sprintf("n=%d/%d off=%d", len(items), total, f.Offset)
	if common != "" {
		note += " host=" + common
	}
	t.note(note)

	for _, it := range items {
		row := []string{
			strconv.Itoa(it.Seq), it.Method, statusCell(it.StatusCode),
			strconv.Itoa(it.ResponseSize), strconv.FormatInt(it.Duration.Milliseconds(), 10),
			dash(contentTypeKeyword(it.ContentType)),
		}
		if wantProto {
			row = append(row, dash(it.Protocol))
		}
		if wantTS {
			row = append(row, it.Timestamp.UTC().Format("15:04:05"))
		}
		if common == "" {
			row = append(row, it.Host)
		}
		row = append(row, pathOf(it.URL))
		t.add(row...)
	}

	out := t.String()
	if f.Offset+len(items) < total {
		out += fmt.Sprintf("\n[%d more; continue with offset=%d]", total-f.Offset-len(items), f.Offset+len(items))
	}
	return out
}

// statusCell renders a missing response as a dash rather than a zero, which would
// otherwise read as a real status code.
func statusCell(code int) string {
	if code == 0 {
		return "-"
	}
	return strconv.Itoa(code)
}

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return truncRunes(p, 120)
}

// maxHintHosts caps the host list in an empty-result hint. The hint exists to
// orient a caller who guessed wrong, not to substitute for history_stats, which
// is where a full enumeration belongs.
const maxHintHosts = 10

// emptyHint is the sentence a listing renders in place of rows. An empty result
// with no explanation is indistinguishable from an empty capture store, so a
// caller that mistyped a host reads it as "the proxy captured nothing" and stops
// — the failure this hint exists to prevent.
//
// It separates the two reasons a host-filtered listing comes back empty, because
// conflating them sends the caller after the wrong one: either no captured host
// contains the substring, in which case naming what was captured is the answer,
// or the host matched and some other filter emptied the result, in which case
// the host is a dead end. With no host filter at all there is nothing to
// diagnose beyond whether anything was captured.
func emptyHint(store *proxy.Store, host string) string {
	captured := store.Count()
	if captured == 0 {
		return "(no requests captured yet)"
	}

	hosts := store.Hosts()
	if strings.TrimSpace(host) == "" {
		return fmt.Sprintf("(no request matched; %d captured across %d hosts)", captured, len(hosts))
	}

	var matched []string
	needle := strings.ToLower(host)
	for _, h := range hosts {
		if strings.Contains(strings.ToLower(h), needle) {
			matched = append(matched, h)
		}
	}
	if len(matched) > 0 {
		return fmt.Sprintf("(host matched %s, but no request passed the other filters)",
			strings.Join(truncHosts(matched), ", "))
	}

	return fmt.Sprintf("(no captured host matches %q; %d requests captured across %d hosts: %s)",
		host, captured, len(hosts), strings.Join(truncHosts(hosts), ", "))
}

// truncHosts caps a host list, naming history_stats as the way to see the rest.
func truncHosts(hosts []string) []string {
	if len(hosts) <= maxHintHosts {
		return hosts
	}
	return append(hosts[:maxHintHosts:maxHintHosts],
		fmt.Sprintf("[%d more; use history_stats]", len(hosts)-maxHintHosts))
}

func commonHost(items []*proxy.CapturedRequest) string {
	if len(items) < 2 {
		return ""
	}
	h := items[0].Host
	for _, it := range items {
		if it.Host != h {
			return ""
		}
	}
	return h
}

// HistoryStats summarizes the capture store without listing it — the cheapest way
// for a client to orient at the start of a session.
func HistoryStats(store *proxy.Store, scope *proxy.Scope, args HistoryArgs) string {
	f := proxy.RequestFilter{Host: args.Host, Method: args.Method, Status: args.Status}
	if args.ScopeOnly && scope != nil {
		f.InScopeFunc = scope.InScope
	}
	items, total := store.List(f)

	byHost := map[string]int{}
	byStatus := map[int]int{}
	for _, it := range items {
		byHost[it.Host]++
		byStatus[it.StatusCode/100]++
	}

	var b strings.Builder
	fmt.Fprintf(&b, "captured=%d matched=%d hosts=%d\n", store.Count(), total, len(byHost))

	classes := make([]int, 0, len(byStatus))
	for c := range byStatus {
		classes = append(classes, c)
	}
	sort.Ints(classes)
	var parts []string
	for _, c := range classes {
		label := strconv.Itoa(c) + "xx"
		if c == 0 {
			label = "none"
		}
		parts = append(parts, fmt.Sprintf("%s=%d", label, byStatus[c]))
	}
	fmt.Fprintf(&b, "status: %s\n", strings.Join(parts, " "))

	type hc struct {
		host string
		n    int
	}
	hosts := make([]hc, 0, len(byHost))
	for h, n := range byHost {
		hosts = append(hosts, hc{h, n})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].n != hosts[j].n {
			return hosts[i].n > hosts[j].n
		}
		return hosts[i].host < hosts[j].host
	})

	t := newTable("n", "host")
	t.empty = "(no hosts)"
	if total == 0 {
		t.empty = emptyHint(store, args.Host)
	}
	for i, h := range hosts {
		if i >= 25 {
			t.note(fmt.Sprintf("[%d more hosts; filter with host=]", len(hosts)-25))
			break
		}
		t.add(strconv.Itoa(h.n), h.host)
	}
	b.WriteString(t.String())
	return b.String()
}

// FingerprintArgs is the argument shape of http.fingerprint.
type FingerprintArgs struct {
	Ref    int    `json:"ref"`
	Refs   []int  `json:"refs"`
	Fields string `json:"fields"` // "+fullhash"
}

// FingerprintRefs computes fingerprints for one or more captured responses.
func FingerprintRefs(store *proxy.Store, args FingerprintArgs) (string, error) {
	refs := args.Refs
	if args.Ref > 0 {
		refs = append([]int{args.Ref}, refs...)
	}
	if len(refs) == 0 {
		return "", fmt.Errorf("ref or refs is required")
	}
	if len(refs) > MaxFingerprintRefs {
		return "", fmt.Errorf("%d refs exceeds the %d-ref limit; call again with a smaller set", len(refs), MaxFingerprintRefs)
	}
	wantFull := strings.Contains(args.Fields, "+fullhash")

	fps := make([]Fingerprint, 0, len(refs))
	for _, ref := range refs {
		item := store.GetBySeq(ref)
		if item == nil {
			fps = append(fps, Fingerprint{Seq: ref, Err: "no captured request with this seq"})
			continue
		}
		if len(item.RespRaw) == 0 {
			fps = append(fps, Fingerprint{Seq: ref, Err: "no response was captured"})
			continue
		}
		fps = append(fps, fingerprintResponse(ref, item.RespRaw, item.Duration.Milliseconds(), wantFull))
	}
	return renderFingerprints(fps, wantFull), nil
}
