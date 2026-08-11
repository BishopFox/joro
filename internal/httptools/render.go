package httptools

import (
	"strings"
	"unicode/utf8"
)

// The encoding rule, applied by every tool in this package:
//
//	More than three rows of uniform shape render as a fixed-width text table with
//	one header line. A single object, or heterogeneous rows, renders as compact
//	JSON.
//
// The reason is arithmetic. A history row as JSON —
//
//	{"seq":412,"method":"GET","status":200,"len":15234,"ms":87,"ct":"html","url":"/a/b?c=1"}
//
// — is roughly 40 tokens, of which the seven keys and their punctuation are about
// 22. That is 55% overhead repeated on every row. The same row in a table is about
// 14 tokens. Over fifty rows the difference is ~700 against ~2,000, and the ratio
// grows with row count. Aligned digit columns and a shared elided host also
// tokenize better than `","status":` does.
//
// Supporting rules, all implemented here so no tool re-derives them:
//   - one header line; columns padded only enough to align, since runs of spaces
//     merge into few tokens and alignment measurably helps column tracking
//   - elide a common prefix into a preamble note rather than repeating it per row
//   - units live in the header, never in cells
//   - an empty result renders as a sentence, not as "[]"

// table accumulates rows for fixed-width rendering.
type table struct {
	cols  []string
	rows  [][]string
	notes []string // preamble lines, printed above the header
	empty string   // rendered when there are no rows
}

func newTable(cols ...string) *table {
	return &table{cols: cols, empty: "(no matches)"}
}

func (t *table) note(s string) {
	if s != "" {
		t.notes = append(t.notes, s)
	}
}

func (t *table) add(cells ...string) {
	t.rows = append(t.rows, cells)
}

func (t *table) String() string {
	var b strings.Builder
	for _, n := range t.notes {
		b.WriteString(n)
		b.WriteByte('\n')
	}
	if len(t.rows) == 0 {
		b.WriteString(t.empty)
		return b.String()
	}

	widths := make([]int, len(t.cols))
	for i, c := range t.cols {
		widths[i] = utf8.RuneCountInString(c)
	}
	for _, row := range t.rows {
		for i, cell := range row {
			if i < len(widths) {
				widths[i] = max(widths[i], utf8.RuneCountInString(cell))
			}
		}
	}

	writeRow(&b, t.cols, widths)
	for _, row := range t.rows {
		writeRow(&b, row, widths)
	}
	return strings.TrimRight(b.String(), "\n")
}

// writeRow pads every cell but the last, so a trailing free-text column (a note, a
// path, a match context) never carries trailing spaces into the model's context.
func writeRow(b *strings.Builder, cells []string, widths []int) {
	for i, cell := range cells {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(cell)
		if i < len(cells)-1 && i < len(widths) {
			if pad := widths[i] - utf8.RuneCountInString(cell); pad > 0 {
				b.WriteString(strings.Repeat(" ", pad))
			}
		}
	}
	b.WriteByte('\n')
}

// escapeCell renders a byte slice as a single safe line: CR, LF and tab become
// escapes and other non-printables become dots.
//
// Without this a match near a newline breaks table alignment and burns tokens on
// ragged output, which is exactly the cost this package exists to avoid.
func escapeCell(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) + 8)
	for _, c := range b {
		switch {
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20 || c == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// truncRunes shortens a display string to n runes, marking the cut. Used for note
// and evidence columns, where an unbounded cell would dominate the table.
func truncRunes(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	out := []rune(s)[:n]
	return string(out) + "…"
}

// dash renders an empty value as a single character, so a missing cell costs one
// token instead of an empty-string quote pair.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
