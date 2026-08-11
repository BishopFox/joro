package httptools

import (
	"strings"
	"unicode/utf8"
)

// hexDump renders bytes in the classic columnar form: an 8-digit offset, sixteen
// bytes per row split into two groups of eight, and an ASCII gutter.
//
// The layout mirrors hexDump in web/src/lib/bytes.ts byte for byte, so an operator
// reading a body in the History Render tab and an automation client reading the
// same bytes see identical output and can talk about the same offsets. The two
// must stay in sync; there is no shared source, because one is TypeScript running
// in the browser and the other is Go running in the proxy.
//
// baseOffset lets a ranged read label rows with their true position in the
// document rather than restarting at zero, which is what makes a hex window
// composable with a second call.
func hexDump(b []byte, baseOffset int) string {
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(b)/16*79 + 16)

	for off := 0; off < len(b); off += 16 {
		row := b[off:min(off+16, len(b))]

		writeHex32(&sb, baseOffset+off)
		sb.WriteString("  ")

		var ascii strings.Builder
		for i := range 16 {
			if i < len(row) {
				c := row[i]
				sb.WriteByte(hexDigits[c>>4])
				sb.WriteByte(hexDigits[c&0x0f])
				sb.WriteByte(' ')
				if c >= 0x20 && c < 0x7f {
					ascii.WriteByte(c)
				} else {
					ascii.WriteByte('.')
				}
			} else {
				sb.WriteString("   ")
			}
			if i == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		sb.WriteString(ascii.String())
		sb.WriteString("|\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func writeHex32(sb *strings.Builder, n int) {
	const hexDigits = "0123456789abcdef"
	for shift := 28; shift >= 0; shift -= 4 {
		sb.WriteByte(hexDigits[(n>>shift)&0x0f])
	}
}

// looksText reports whether a slice can be handed to a model as text.
//
// The bar is valid UTF-8 with under half a percent of bytes in the control ranges.
// It is stricter than detect's binary sniff on purpose: that one decides whether to
// scan for secrets, where a false negative loses a finding, while this one decides
// whether to put bytes into a model's context, where a false positive produces
// mojibake that wastes tokens and teaches the model nothing.
func looksText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(b) {
		return false
	}
	odd := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f {
			odd++
		}
	}
	return float64(odd)/float64(len(b)) < 0.005
}
