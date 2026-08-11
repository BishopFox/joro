package httptools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// maxNormalizeBytes bounds structural normalization. Beyond it the prefix is
// hashed and the total length folded in, so two files sharing a prefix but
// differing in length still get different structural hashes.
const maxNormalizeBytes = 512 << 10

// Volatile-value patterns, applied in the order declared. The order is
// load-bearing and each entry earns its place:
//
//  1. long hex runs must go before bare digit runs, or a CSRF token is shredded
//     into digit noise and partially survives as letters
//  2. UUIDs need their own pass because their dashes break the hex-run pattern
//  3. base64 runs catch JWTs, nonces and cache-busted asset hashes in script srcs
//  4. bare digit runs go last, so dates and hashes are already consumed
//
// The governing rule for what belongs here: normalize only values the server would
// have chosen differently on a second identical request. Anything else that
// differs between two responses is a real difference, and hiding it would make the
// structural hash lie.
var volatilePatterns = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), "U"},
	{regexp.MustCompile(`(?i)\b[0-9a-f]{8,}\b`), "H"},
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?`), "T"},
	{regexp.MustCompile(`(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT`), "T"},
	{regexp.MustCompile(`[A-Za-z0-9+/_-]{20,}={0,2}`), "B"},
	{regexp.MustCompile(`\d+`), "0"},
}

var wsRun = regexp.MustCompile(`[ \t]+`)

// volatileHeaders are excluded from the header component of a structural hash:
// their values change per request without the response meaning anything different.
// Names, not values, are hashed, so this catches "the WAF started adding a header"
// while ignoring per-request identifiers.
var volatileHeaders = map[string]bool{
	"date": true, "set-cookie": true, "content-length": true, "age": true,
	"expires": true, "etag": true, "last-modified": true, "x-request-id": true,
	"cf-ray": true, "report-to": true, "nel": true, "x-amzn-requestid": true,
	"x-amzn-trace-id": true, "x-served-by": true, "x-timer": true,
}

func volatileHeaderName(name string) bool {
	n := strings.ToLower(name)
	if volatileHeaders[n] {
		return true
	}
	return strings.HasPrefix(n, "x-amz-") || strings.HasPrefix(n, "x-trace")
}

// normalize collapses volatile values in a body so two renderings of the same page
// compare equal.
//
// It deliberately does not lowercase. Case carries real structure in HTML and
// JavaScript, and folding it would make "Error" and "error" collide — a
// distinction that matters during triage.
func normalize(body []byte) []byte {
	src := body
	truncated := false
	if len(src) > maxNormalizeBytes {
		src = src[:maxNormalizeBytes]
		truncated = true
	}

	out := bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n"))
	for _, p := range volatilePatterns {
		out = p.re.ReplaceAll(out, []byte(p.with))
	}
	out = wsRun.ReplaceAll(out, []byte(" "))

	lines := bytes.Split(out, []byte("\n"))
	kept := lines[:0]
	for _, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) > 0 {
			kept = append(kept, ln)
		}
	}
	out = bytes.Join(kept, []byte("\n"))

	if truncated {
		out = append(out, []byte("\n+"+strconv.Itoa(len(body)))...)
	}
	return out
}

// Fingerprint is the compact description of one response. Every field earns its
// tokens; see the field comments for what each one is for.
type Fingerprint struct {
	Seq        int    `json:"seq"`
	Status     int    `json:"status"`
	Len        int    `json:"len"` // body length AFTER decompression; Content-Length lies under gzip
	DurationMs int64  `json:"ms"`
	CT         string `json:"ct"`

	// BodyHash is sha256 of the exact body, first 8 hex. StructHash folds the
	// status, the surviving header names and the normalized body — it is the field
	// that makes this tool worth building, because it collapses "same page,
	// different nonce" to a single repeated string a client compares reliably.
	BodyHash   string `json:"bhash"`
	StructHash string `json:"shash"`

	// Words and Lines use the fuzzer's exact definitions, so a fingerprint row is
	// directly comparable to a fuzzer.result row.
	Words int `json:"words"`
	Lines int `json:"lines"`

	// Note is one derived string: a redirect Location, else an HTML title, else the
	// first JSON key. This single column is what turns a table of hashes into
	// something a client can reason about.
	Note   string `json:"note,omitempty"`
	Server string `json:"server,omitempty"`

	Decoded   string `json:"decoded,omitempty"`
	NormTrunc bool   `json:"normTrunc,omitempty"`
	FullHash  string `json:"fullHash,omitempty"`
	Err       string `json:"err,omitempty"`
}

var (
	titleRe    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	jsonKeyRe  = regexp.MustCompile(`"([^"]{1,40})"\s*:`)
	spaceRunRe = regexp.MustCompile(`\s+`)
)

// fingerprintResponse computes a Fingerprint from raw response bytes.
func fingerprintResponse(seq int, raw []byte, durationMs int64, wantFull bool) Fingerprint {
	m := parseMessage(raw, true)

	bodySum := sha256.Sum256(m.Body)
	fp := Fingerprint{
		Seq:        seq,
		Status:     m.Status,
		Len:        len(m.Body),
		DurationMs: durationMs,
		CT:         m.contentType(),
		BodyHash:   hex.EncodeToString(bodySum[:4]),
		Words:      len(bytes.Fields(m.Body)),
		Lines:      countLines(m.Body),
		Decoded:    m.Decoded,
		Server:     firstToken(m.Header.Get("Server")),
		Note:       deriveNote(m),
	}
	if wantFull {
		fp.FullHash = hex.EncodeToString(bodySum[:])
	}
	fp.NormTrunc = len(m.Body) > maxNormalizeBytes
	fp.StructHash = structHash(m)
	return fp
}

// structHash folds status, surviving header names and the normalized body.
//
// Including the status is essential: an empty 200 and an empty 403 must not share
// a structural hash, and with an empty body the header and body components are
// identical. That is the negative control the test pins.
func structHash(m *message) string {
	names := make([]string, 0, len(m.Header))
	for name := range m.Header {
		if !volatileHeaderName(name) {
			names = append(names, strings.ToLower(name))
		}
	}
	sort.Strings(names)

	h := sha256.New()
	h.Write([]byte(strconv.Itoa(m.Status)))
	h.Write([]byte{'\n'})
	h.Write([]byte(strings.Join(names, ",")))
	h.Write([]byte{'\n'})
	h.Write(normalize(m.Body))
	return hex.EncodeToString(h.Sum(nil)[:4])
}

// deriveNote produces the single human-legible column, in priority order.
func deriveNote(m *message) string {
	if loc := m.Header.Get("Location"); loc != "" {
		return truncRunes("Location:"+loc, 60)
	}
	body := m.Body
	if len(body) > 64<<10 {
		body = body[:64<<10] // the title or first key is near the top or not there
	}
	if mm := titleRe.FindSubmatch(body); mm != nil {
		t := strings.TrimSpace(spaceRunRe.ReplaceAllString(string(mm[1]), " "))
		if t != "" {
			return truncRunes(t, 60)
		}
	}
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) || bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		if mm := jsonKeyRe.FindSubmatch(body); mm != nil {
			return truncRunes("{"+string(mm[1])+":…", 60)
		}
	}
	return ""
}

func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return bytes.Count(b, []byte{'\n'}) + 1
}

func firstToken(s string) string {
	if i := strings.IndexAny(s, " \t;"); i > 0 {
		return s[:i]
	}
	return s
}

// renderFingerprints emits the batch table form. The columns are ordered so the
// two hashes sit adjacent: identical structural hashes are then visually identical
// down the column, which is the comparison a client makes most reliably.
func renderFingerprints(fps []Fingerprint, wantFull bool) string {
	cols := []string{"seq", "status", "len", "ms", "ct", "bhash", "shash", "words", "lines", "note"}
	if wantFull {
		cols = append(cols[:6], append([]string{"fullhash"}, cols[6:]...)...)
	}
	t := newTable(cols...)
	t.empty = "(no responses)"
	for _, f := range fps {
		if f.Err != "" {
			t.add(strconv.Itoa(f.Seq), "-", "-", "-", "-", "-", "-", "-", "-", "err="+truncRunes(f.Err, 60))
			continue
		}
		row := []string{
			strconv.Itoa(f.Seq), strconv.Itoa(f.Status), strconv.Itoa(f.Len),
			strconv.FormatInt(f.DurationMs, 10), f.CT, f.BodyHash,
		}
		if wantFull {
			row = append(row, f.FullHash)
		}
		row = append(row, f.StructHash, strconv.Itoa(f.Words), strconv.Itoa(f.Lines), dash(f.Note))
		t.add(row...)
	}
	return t.String()
}
