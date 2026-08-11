package httptools

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strings"
)

// Diff caps.
const (
	DefaultMaxHunks     = 12
	MaxMaxHunks         = 40
	DefaultContextLines = 2
	MaxContextLines     = 5
	// maxHunkLines bounds a single hunk. maxHunks caps how many hunks are shown
	// but says nothing about their size, and two documents that share no lines at
	// all produce one hunk containing every line of both — tens of thousands of
	// tokens, which is precisely what this package exists to avoid. The cap is per
	// hunk rather than overall so a diff with several changes still shows all of
	// them.
	maxHunkLines = 60
	// dpBudget bounds the LCS matrix. Backtracking needs the full matrix, so it is
	// allocated only under this bound: 4e6 int32 cells is about 16 MB and ten
	// milliseconds.
	dpBudget = 4_000_000
	// maxLinesPerSide is the hard ceiling before we stop reading at all.
	maxLinesPerSide = 50_000
	maxDiffLineLen  = 200
)

// sensitiveHeaders have their values suppressed in a diff. A diff is precisely
// where a live session token would otherwise be copied into a model's context, so
// these report name and presence only.
var sensitiveHeaders = map[string]bool{
	"set-cookie": true, "cookie": true, "authorization": true,
	"proxy-authorization": true, "x-api-key": true, "x-auth-token": true,
}

// diffLoudHeaders are volatile-valued headers that a diff still reports.
//
// This set exists because "volatile" means two different things in two places.
// For the structural hash, a header whose value changes per request must be
// excluded or nothing would ever match. For a diff, some of those changes are the
// finding: "the session cookie was reissued" is often exactly what an operator is
// looking for, and since sensitiveHeaders already redacts the value, reporting it
// leaks nothing. So Set-Cookie is volatile for hashing and loud for diffing.
//
// Content-Length is the reverse case and is deliberately absent: the body section
// already prints both sizes, so repeating it in the header list is noise.
var diffLoudHeaders = map[string]bool{
	"set-cookie": true,
}

// DiffArgs is the argument shape of http.diff.
type DiffArgs struct {
	A              int    `json:"a"`
	B              int    `json:"b"`
	Part           string `json:"part"`
	IgnoreVolatile *bool  `json:"ignoreVolatile"`
	MaxHunks       int    `json:"maxHunks"`
	ContextLines   int    `json:"contextLines"`
}

// DiffMessages compares two captured messages and renders a compact structured
// diff.
//
// Status, headers and body are three separate sections. They are different kinds
// of evidence, and folding them together lets a large body diff drown the header
// change that usually explains it.
func DiffMessages(aRaw, bRaw []byte, aSeq, bSeq int, args DiffArgs) string {
	ignoreVolatile := args.IgnoreVolatile == nil || *args.IgnoreVolatile
	maxHunks := clampInt(args.MaxHunks, DefaultMaxHunks, 1, MaxMaxHunks)
	ctxLines := clampInt(args.ContextLines, DefaultContextLines, 0, MaxContextLines)

	am := parseMessage(aRaw, true)
	bm := parseMessage(bRaw, true)

	var out strings.Builder
	part := orDefault(args.Part, "resp")
	fmt.Fprintf(&out, "diff a=%d b=%d part=%s volatile=%s\n", aSeq, bSeq, part, ignoredWord(ignoreVolatile))

	// Status.
	if am.Status != bm.Status {
		fmt.Fprintf(&out, "status: %d -> %d\n", am.Status, bm.Status)
	} else {
		fmt.Fprintf(&out, "status: %d (unchanged)\n", am.Status)
	}

	// Headers.
	out.WriteString(diffHeaders(am.Header, bm.Header, ignoreVolatile))

	// Body.
	out.WriteString(diffBodies(am, bm, ignoreVolatile, maxHunks, ctxLines))
	return strings.TrimRight(out.String(), "\n")
}

func ignoredWord(b bool) string {
	if b {
		return "ignored"
	}
	return "kept"
}

// diffHeaders reports added, removed and changed headers.
//
// A difference in ordering only collapses to a single line rather than churning
// out a pair of +/- rows per header, which is otherwise the bulk of a diff between
// two responses from a load-balanced pair.
//
// ignoreVolatile suppresses headers whose value the server would have chosen
// differently on a second identical request — the same set structHash excludes.
// Without this, Date changes on literally every diff, and a per-request id or a
// cf-ray does too, so the section an operator reads first is mostly noise. A
// header appearing or disappearing entirely is still reported: "the WAF started
// setting this" is a real finding even for a volatile-valued header.
func diffHeaders(a, b http.Header, ignoreVolatile bool) string {
	names := map[string]bool{}
	for n := range a {
		names[http.CanonicalHeaderKey(n)] = true
	}
	for n := range b {
		names[http.CanonicalHeaderKey(n)] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	suppressed := 0
	var lines []string
	for _, n := range sorted {
		if ignoreVolatile && volatileHeaderName(n) && !diffLoudHeaders[strings.ToLower(n)] {
			_, aok := a[http.CanonicalHeaderKey(n)]
			_, bok := b[http.CanonicalHeaderKey(n)]
			if aok == bok {
				// Present on both sides with differing values: volatile noise.
				suppressed++
				continue
			}
		}
		av, aok := joinValues(a, n)
		bv, bok := joinValues(b, n)
		lower := strings.ToLower(n)
		switch {
		case aok && !bok:
			lines = append(lines, "  - "+n+": "+headerValue(lower, av))
		case !aok && bok:
			lines = append(lines, "  + "+n+": "+headerValue(lower, bv))
		case aok && bok && av != bv:
			if sensitiveHeaders[lower] {
				lines = append(lines, "  ~ "+n+": <value changed, redacted>")
			} else {
				lines = append(lines, "  ~ "+n+": "+truncRunes(av, 80)+" -> "+truncRunes(bv, 80))
			}
		}
	}

	suffix := ""
	if suppressed > 0 {
		suffix = fmt.Sprintf(" (%d volatile header(s) ignored)", suppressed)
	}
	if len(lines) == 0 {
		if headerOrder(a) != headerOrder(b) {
			return "headers: header order differs, values identical" + suffix + "\n"
		}
		return "headers: unchanged" + suffix + "\n"
	}
	return "headers:" + suffix + "\n" + strings.Join(lines, "\n") + "\n"
}

func headerValue(lowerName, v string) string {
	if sensitiveHeaders[lowerName] {
		return "<present, redacted>"
	}
	return truncRunes(v, 80)
}

// joinValues sorts a multi-valued header so a reordering is not reported as a
// change; the order of repeated headers is not semantically meaningful here.
func joinValues(h http.Header, name string) (string, bool) {
	vs, ok := h[http.CanonicalHeaderKey(name)]
	if !ok {
		return "", false
	}
	cp := append([]string(nil), vs...)
	sort.Strings(cp)
	return strings.Join(cp, ", "), true
}

func headerOrder(h http.Header) string {
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func diffBodies(am, bm *message, ignoreVolatile bool, maxHunks, ctxLines int) string {
	aLines := splitLines(am.Body)
	bLines := splitLines(bm.Body)

	var head strings.Builder
	fmt.Fprintf(&head, "body: %d -> %d bytes, shash %s -> %s",
		len(am.Body), len(bm.Body), structHash(am), structHash(bm))

	truncatedRead := false
	if len(aLines) > maxLinesPerSide {
		aLines, truncatedRead = aLines[:maxLinesPerSide], true
	}
	if len(bLines) > maxLinesPerSide {
		bLines, truncatedRead = bLines[:maxLinesPerSide], true
	}

	// Hash lines for comparison, optionally after normalizing volatile values.
	// The hash is what gets compared; the original text is what gets displayed.
	// Showing the normalized line instead would print "<p>0</p>" where the page
	// said "<p>4213</p>", which is actively misleading.
	aKeys := hashLines(aLines, ignoreVolatile)
	bKeys := hashLines(bLines, ignoreVolatile)

	// Reduction 1: trim the common prefix and suffix. On the dominant real case —
	// the same page with one field changed — this takes four thousand lines to
	// under fifty in a single linear pass, and it is by a wide margin the
	// highest-value step here.
	pre := 0
	for pre < len(aKeys) && pre < len(bKeys) && aKeys[pre] == bKeys[pre] {
		pre++
	}
	suf := 0
	for suf < len(aKeys)-pre && suf < len(bKeys)-pre &&
		aKeys[len(aKeys)-1-suf] == bKeys[len(bKeys)-1-suf] {
		suf++
	}
	aMid, bMid := aKeys[pre:len(aKeys)-suf], bKeys[pre:len(bKeys)-suf]

	if len(aMid) == 0 && len(bMid) == 0 {
		head.WriteString(", identical\n")
		if truncatedRead {
			head.WriteString("[note: compared the first 50000 lines of each side]\n")
		}
		return head.String()
	}

	// Reduction 2: drop lines whose hash appears on only one side. Such a line
	// cannot be part of any common subsequence, so removing it is lossless for the
	// LCS while typically halving what remains (Hunt-Szymanski's trick).
	aIdx, bIdx := dropUnique(aMid, bMid)

	if len(aIdx)*len(bIdx) > dpBudget {
		// Degrade loudly. A client told why it got the cheaper answer will narrow
		// with http_search; a client that believes it saw a positional diff will
		// reason about "where" from data that has no where.
		fmt.Fprintf(&head, ", %d hunks not computed\n", 0)
		fmt.Fprintf(&head, "[too large for positional diff: %d x %d lines after reduction — showing unordered line delta]\n",
			len(aIdx), len(bIdx))
		head.WriteString(multisetDelta(aLines, bLines, aKeys, bKeys, maxHunks*3))
		return head.String()
	}

	ops := lcsDiff(aIdx, bIdx, aMid, bMid, pre)
	hunks := buildHunks(ops, aLines, bLines, ctxLines)

	shown := min(len(hunks), maxHunks)
	fmt.Fprintf(&head, ", %d hunks", len(hunks))
	if shown < len(hunks) {
		fmt.Fprintf(&head, " (showing %d)", shown)
	}
	head.WriteByte('\n')
	if truncatedRead {
		head.WriteString("[note: compared the first 50000 lines of each side]\n")
	}
	for _, h := range hunks[:shown] {
		head.WriteString(h)
	}
	if shown < len(hunks) {
		fmt.Fprintf(&head, "[%d more hunks suppressed; raise maxHunks, set ignoreVolatile, or narrow with http_search]\n",
			len(hunks)-shown)
	}
	return head.String()
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return strings.Split(s, "\n")
}

func hashLines(lines []string, ignoreVolatile bool) []uint64 {
	out := make([]uint64, len(lines))
	for i, ln := range lines {
		text := ln
		if ignoreVolatile {
			text = string(normalize([]byte(ln)))
		}
		h := fnv.New64a()
		h.Write([]byte(text))
		out[i] = h.Sum64()
	}
	return out
}

// dropUnique returns the indices (into the trimmed slices) of lines whose hash
// appears on both sides.
func dropUnique(a, b []uint64) (aIdx, bIdx []int) {
	inB := make(map[uint64]int, len(b))
	for _, k := range b {
		inB[k]++
	}
	inA := make(map[uint64]int, len(a))
	for _, k := range a {
		inA[k]++
	}
	for i, k := range a {
		if inB[k] > 0 {
			aIdx = append(aIdx, i)
		}
	}
	for i, k := range b {
		if inA[k] > 0 {
			bIdx = append(bIdx, i)
		}
	}
	return aIdx, bIdx
}

// op is one edit in the diff, in original line coordinates.
type op struct {
	kind byte // ' ' equal, '-' delete from a, '+' insert from b
	aLn  int  // 0-based index into the full a line slice, or -1
	bLn  int
}

// lcsDiff runs the DP over the reduced index sets and expands the result back into
// full-document coordinates, re-inserting the unique lines that reduction 2 pulled
// out as plain deletes and inserts.
func lcsDiff(aIdx, bIdx []int, aMid, bMid []uint64, offset int) []op {
	n, m := len(aIdx), len(bIdx)
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if aMid[aIdx[i]] == bMid[bIdx[j]] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}

	// Walk the matrix, collecting the matched pairs in original coordinates.
	type pair struct{ a, b int }
	var matches []pair
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case aMid[aIdx[i]] == bMid[bIdx[j]]:
			matches = append(matches, pair{aIdx[i], bIdx[j]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}

	// Emit deletes and inserts for everything between consecutive matches.
	var ops []op
	aPos, bPos := 0, 0
	emitGap := func(aEnd, bEnd int) {
		for ; aPos < aEnd; aPos++ {
			ops = append(ops, op{'-', offset + aPos, -1})
		}
		for ; bPos < bEnd; bPos++ {
			ops = append(ops, op{'+', -1, offset + bPos})
		}
	}
	for _, mt := range matches {
		emitGap(mt.a, mt.b)
		ops = append(ops, op{' ', offset + mt.a, offset + mt.b})
		aPos, bPos = mt.a+1, mt.b+1
	}
	emitGap(len(aMid), len(bMid))
	return ops
}

// buildHunks turns an op list into unified-format hunks with context, merging
// hunks that sit closer together than twice the context width.
func buildHunks(ops []op, aLines, bLines []string, ctxLines int) []string {
	type span struct{ start, end int } // indices into ops
	var spans []span
	for i := 0; i < len(ops); i++ {
		if ops[i].kind == ' ' {
			continue
		}
		start, end := i, i
		for end+1 < len(ops) {
			// Look ahead across up to 2*ctx equal lines for another change.
			gap := 0
			k := end + 1
			for k < len(ops) && ops[k].kind == ' ' && gap < 2*ctxLines+1 {
				gap++
				k++
			}
			if k < len(ops) && ops[k].kind != ' ' && gap <= 2*ctxLines {
				end = k
				continue
			}
			break
		}
		spans = append(spans, span{start, end})
		i = end
	}

	var hunks []string
	for _, sp := range spans {
		lo := max(0, sp.start-ctxLines)
		hi := min(len(ops), sp.end+ctxLines+1)

		aStart, bStart, aCount, bCount := -1, -1, 0, 0
		var body strings.Builder
		emitted, suppressedLines := 0, 0
		for _, o := range ops[lo:hi] {
			if emitted >= maxHunkLines {
				suppressedLines++
				// Still count the line so the @@ header describes the real span.
				switch o.kind {
				case ' ':
					aCount++
					bCount++
				case '-':
					aCount++
				case '+':
					bCount++
				}
				continue
			}
			emitted++
			switch o.kind {
			case ' ':
				aCount++
				bCount++
				if aStart < 0 {
					aStart, bStart = o.aLn, o.bLn
				}
				body.WriteString("  " + safeLine(aLines, o.aLn) + "\n")
			case '-':
				aCount++
				if aStart < 0 {
					aStart, bStart = o.aLn, max(0, bStart)
				}
				body.WriteString("- " + safeLine(aLines, o.aLn) + "\n")
			case '+':
				bCount++
				if bStart < 0 {
					bStart = o.bLn
				}
				if aStart < 0 {
					aStart = 0
				}
				body.WriteString("+ " + safeLine(bLines, o.bLn) + "\n")
			}
		}
		if suppressedLines > 0 {
			fmt.Fprintf(&body, "[%d more changed lines in this hunk; narrow with http_search or read the range with http_read]\n",
				suppressedLines)
		}
		hunks = append(hunks, fmt.Sprintf("@@ -%d,%d +%d,%d @@\n%s",
			max(aStart, 0)+1, aCount, max(bStart, 0)+1, bCount, body.String()))
	}
	return hunks
}

func safeLine(lines []string, i int) string {
	if i < 0 || i >= len(lines) {
		return ""
	}
	return truncRunes(escapeCell([]byte(lines[i])), maxDiffLineLen)
}

// multisetDelta is the degraded path: an unordered count of lines present on one
// side and not the other. It says nothing about position, which is exactly why the
// caller labels it as such.
func multisetDelta(aLines, bLines []string, aKeys, bKeys []uint64, limit int) string {
	counts := map[uint64]int{}
	sample := map[uint64]string{}
	for i, k := range aKeys {
		counts[k]--
		if _, ok := sample[k]; !ok {
			sample[k] = aLines[i]
		}
	}
	for i, k := range bKeys {
		counts[k]++
		if _, ok := sample[k]; !ok {
			sample[k] = bLines[i]
		}
	}

	type entry struct {
		delta int
		text  string
	}
	var entries []entry
	for k, d := range counts {
		if d != 0 {
			entries = append(entries, entry{d, sample[k]})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return abs(entries[i].delta) > abs(entries[j].delta) })

	var b strings.Builder
	for i, e := range entries {
		if i >= limit {
			fmt.Fprintf(&b, "[%d more changed lines suppressed]\n", len(entries)-limit)
			break
		}
		sign := "+"
		if e.delta < 0 {
			sign = "-"
		}
		fmt.Fprintf(&b, "%s%3d %s\n", sign, abs(e.delta),
			truncRunes(escapeCell([]byte(e.text)), maxDiffLineLen))
	}
	if b.Len() == 0 {
		return "(no line-level differences)\n"
	}
	return b.String()
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
