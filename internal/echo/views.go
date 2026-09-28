package echo

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
)

// view is a buffer to search plus the mapping back to where its bytes came
// from. off holds one entry per byte of b plus a trailing sentinel, so a match
// on [i,j) maps to the source range [off[i], off[j]) exactly — including when
// the last decoded byte was written by a multi-byte escape. A nil off means the
// identity mapping, which spares the common case an allocation the size of the
// body.
type view struct {
	kind Transform
	b    []byte
	off  []int32
}

// at maps an index in v.b, or the one-past-the-end index, to a source offset.
func (v view) at(i int) int {
	if v.off == nil {
		return i
	}
	if i >= len(v.off) {
		return int(v.off[len(v.off)-1])
	}
	return int(v.off[i])
}

// decoder strips one layer of encoding, returning the decoded bytes and their
// offset map into src. changed is false when src held nothing to decode, which
// is the signal to skip the view entirely rather than search a copy of a buffer
// already searched.
type decoder struct {
	kind   Transform
	marker byte // a byte src must contain for this decoder to do anything
	fn     func(src []byte) (out []byte, off []int32, changed bool)
}

var decoders = []decoder{
	{TransformPercent, '%', decodePercent},
	{TransformHTMLEntity, '&', decodeHTMLEntity},
	{TransformJSString, '\\', decodeJSString},
}

// buildViews returns every buffer worth searching for a literal value. The
// marker check is what keeps the common response at two passes: a body with no
// '&' in it cannot be hiding an entity-encoded value, and proving that costs one
// scan rather than a decode and a search.
func buildViews(src []byte, cfg Config) []view {
	views := []view{{kind: TransformIdentity, b: src}}
	if len(src) == 0 {
		return views
	}

	type layer struct {
		v    view
		name Transform
	}
	var first []layer
	for _, d := range decoders {
		if bytes.IndexByte(src, d.marker) < 0 {
			continue
		}
		out, off, changed := d.fn(src)
		if !changed || bytes.Equal(out, src) {
			continue
		}
		v := view{kind: d.kind, b: out, off: off}
		views = append(views, v)
		first = append(first, layer{v, d.kind})
	}

	if cfg.TransformDepth >= 2 {
		for _, l := range first {
			for _, d := range decoders {
				// A doubled js-string decode is not a shape anything produces,
				// and html-then-html folds into a single pass already.
				if d.kind == TransformJSString || l.name == TransformJSString {
					continue
				}
				if d.kind == TransformHTMLEntity && l.name == TransformHTMLEntity {
					continue
				}
				if bytes.IndexByte(l.v.b, d.marker) < 0 {
					continue
				}
				out, off, changed := d.fn(l.v.b)
				if !changed {
					continue
				}
				views = append(views, view{
					kind: composeName(l.name, d.kind),
					b:    out,
					off:  composeOffsets(l.v, off),
				})
			}
		}
	}

	if cfg.Base64 {
		views = append(views, base64Views(src)...)
	}
	return views
}

// composeName joins two transform names outermost first, so the name reads in
// the order a decoder strips them.
func composeName(outer, inner Transform) Transform {
	switch {
	case outer == TransformPercent && inner == TransformHTMLEntity:
		return TransformPercentHTML
	case outer == TransformPercent && inner == TransformPercent:
		return TransformPercentTwice
	case outer == TransformHTMLEntity && inner == TransformPercent:
		return TransformHTMLPercent
	}
	return Transform(string(outer) + "+" + string(inner))
}

// composeOffsets threads an inner decoder's map through the outer view's, which
// is the whole reason a decoder returns a map rather than a string: composing
// two layers is composing two lookups.
func composeOffsets(outer view, inner []int32) []int32 {
	out := make([]int32, len(inner))
	for i, v := range inner {
		out[i] = int32(outer.at(int(v)))
	}
	return out
}

func decodePercent(src []byte) ([]byte, []int32, bool) {
	out := make([]byte, 0, len(src))
	off := make([]int32, 0, len(src)+1)
	changed := false
	for i := 0; i < len(src); i++ {
		if src[i] == '%' && i+2 < len(src) && isHex(src[i+1]) && isHex(src[i+2]) {
			out = append(out, unhex(src[i+1])<<4|unhex(src[i+2]))
			off = append(off, int32(i))
			i += 2
			changed = true
			continue
		}
		out = append(out, src[i])
		off = append(off, int32(i))
	}
	off = append(off, int32(len(src)))
	return out, off, changed
}

// namedEntities covers the entities that carry security meaning plus the few
// an application is likely to emit around them. The full HTML5 table is
// thousands of entries and none of the rest changes a verdict.
var namedEntities = map[string]byte{
	"lt": '<', "gt": '>', "amp": '&', "quot": '"', "apos": '\'',
	"sol": '/', "bsol": '\\', "lpar": '(', "rpar": ')', "colon": ':',
	"semi": ';', "equals": '=', "grave": '`', "lbrace": '{', "rbrace": '}',
	"lsqb": '[', "rsqb": ']', "excl": '!', "num": '#', "dollar": '$',
	"percnt": '%', "ast": '*', "plus": '+', "comma": ',', "period": '.',
	"quest": '?', "commat": '@', "verbar": '|', "tilde": '~', "nbsp": ' ',
	"Tab": '\t', "NewLine": '\n', "space": ' ',
}

// decodeHTMLEntity expands named and numeric references. A reference is
// accepted without its terminating semicolon, because browsers do and the point
// is to see what a browser would see.
func decodeHTMLEntity(src []byte) ([]byte, []int32, bool) {
	out := make([]byte, 0, len(src))
	off := make([]int32, 0, len(src)+1)
	changed := false
	for i := 0; i < len(src); i++ {
		if src[i] != '&' {
			out = append(out, src[i])
			off = append(off, int32(i))
			continue
		}
		b, width, ok := readEntity(src[i:])
		if !ok {
			out = append(out, src[i])
			off = append(off, int32(i))
			continue
		}
		out = append(out, b...)
		for range b {
			off = append(off, int32(i))
		}
		i += width - 1
		changed = true
	}
	off = append(off, int32(len(src)))
	return out, off, changed
}

// readEntity reads one reference at the start of s, returning its bytes and the
// length consumed.
func readEntity(s []byte) ([]byte, int, bool) {
	if len(s) < 3 {
		return nil, 0, false
	}
	// Bound the scan: a reference longer than this is not one.
	end := len(s)
	if end > 34 {
		end = 34
	}
	semi := bytes.IndexByte(s[:end], ';')

	if s[1] == '#' {
		j, base := 2, 10
		if j < end && (s[j] == 'x' || s[j] == 'X') {
			j, base = j+1, 16
		}
		k := j
		for k < end && isDigitIn(s[k], base) {
			k++
		}
		if k == j {
			return nil, 0, false
		}
		n, err := strconv.ParseInt(string(s[j:k]), base, 32)
		if err != nil || n <= 0 || n > 0x10FFFF {
			return nil, 0, false
		}
		width := k
		if k < end && s[k] == ';' {
			width = k + 1
		}
		return []byte(string(rune(n))), width, true
	}

	if semi > 1 {
		if b, ok := namedEntities[string(s[1:semi])]; ok {
			return []byte{b}, semi + 1, true
		}
	}
	// Semicolon-less named form, longest match first.
	for n := 8; n >= 2; n-- {
		if 1+n > len(s) {
			continue
		}
		if b, ok := namedEntities[string(s[1:1+n])]; ok {
			return []byte{b}, 1 + n, true
		}
	}
	return nil, 0, false
}

func isDigitIn(c byte, base int) bool {
	if base == 16 {
		return isHex(c)
	}
	return c >= '0' && c <= '9'
}

// decodeJSString expands the backslash escapes a JavaScript or JSON string
// literal uses. It runs over the whole buffer rather than over located literals,
// because locating them first would need the parse this is feeding.
func decodeJSString(src []byte) ([]byte, []int32, bool) {
	out := make([]byte, 0, len(src))
	off := make([]int32, 0, len(src)+1)
	changed := false
	emit := func(bs []byte, at int) {
		out = append(out, bs...)
		for range bs {
			off = append(off, int32(at))
		}
	}
	for i := 0; i < len(src); i++ {
		if src[i] != '\\' || i+1 >= len(src) {
			out = append(out, src[i])
			off = append(off, int32(i))
			continue
		}
		c := src[i+1]
		switch {
		case c == 'x' && i+3 < len(src) && isHex(src[i+2]) && isHex(src[i+3]):
			emit([]byte{unhex(src[i+2])<<4 | unhex(src[i+3])}, i)
			i += 3
			changed = true
		case c == 'u' && i+5 < len(src) && allHex(src[i+2:i+6]):
			n, _ := strconv.ParseInt(string(src[i+2:i+6]), 16, 32)
			emit([]byte(string(rune(n))), i)
			i += 5
			changed = true
		case c == 'n':
			emit([]byte{'\n'}, i)
			i++
			changed = true
		case c == 'r':
			emit([]byte{'\r'}, i)
			i++
			changed = true
		case c == 't':
			emit([]byte{'\t'}, i)
			i++
			changed = true
		case strings.IndexByte(`"'\/`, c) >= 0:
			emit([]byte{c}, i)
			i++
			changed = true
		default:
			out = append(out, src[i])
			off = append(off, int32(i))
		}
	}
	off = append(off, int32(len(src)))
	return out, off, changed
}

func allHex(b []byte) bool {
	for _, c := range b {
		if !isHex(c) {
			return false
		}
	}
	return true
}

// minBase64Run is the shortest run worth decoding: 16 characters carry 12
// bytes, below which a "value" is too short to have been worth sending.
const minBase64Run = 16

func isB64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '_' || c == '-'
}

// base64Runs locates candidate blobs. This is a byte scan rather than a regular
// expression because it runs over every response body: the equivalent pattern
// costs more than the rest of the analysis put together.
func base64Runs(src []byte) [][2]int {
	var out [][2]int
	for i := 0; i < len(src); {
		if !isB64Byte(src[i]) {
			i++
			continue
		}
		j := i
		for j < len(src) && isB64Byte(src[j]) {
			j++
		}
		end := j
		for end < len(src) && src[end] == '=' && end-j < 2 {
			end++
		}
		if j-i >= minBase64Run {
			out = append(out, [2]int{i, end})
			if len(out) >= maxBase64Runs {
				return out
			}
		}
		i = end
		if i == j && i < len(src) {
			i++
		}
	}
	return out
}

// maxBase64Runs bounds the per-response run count. A page of image data URIs
// would otherwise turn one response into thousands of views.
const maxBase64Runs = 256

// base64Views decodes each base64-shaped run into a view of its own, with
// offsets pointing back into that run. Decoding located runs rather than
// encoding the needle is what makes this exact: an encoded value's spelling
// depends on its offset within the blob, so a needle-side search would have to
// try every alignment and still could not report where the match landed.
func base64Views(src []byte) []view {
	locs := base64Runs(src)
	if len(locs) == 0 {
		return nil
	}
	views := make([]view, 0, len(locs))
	for _, loc := range locs {
		run := src[loc[0]:loc[1]]
		dec, ok := decodeBase64(run)
		if !ok || len(dec) < 3 || !looksDecodable(dec) {
			continue
		}
		// Every decoded byte maps to the start of the group that produced it;
		// three source characters per four decoded bytes is close enough to
		// point an operator at the right place in the blob.
		off := make([]int32, len(dec)+1)
		for i := range dec {
			off[i] = int32(loc[0] + i/3*4)
		}
		off[len(dec)] = int32(loc[1])
		views = append(views, view{kind: TransformBase64, b: dec, off: off})
	}
	return views
}

func decodeBase64(run []byte) ([]byte, bool) {
	s := strings.TrimRight(string(run), "=")
	if strings.ContainsAny(s, "-_") {
		if d, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			return d, true
		}
		return nil, false
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return d, true
	}
	return nil, false
}

// looksDecodable rejects a run that decoded to binary. Any long alphanumeric
// token decodes to something; only a printable result is a value an operator
// sent.
func looksDecodable(b []byte) bool {
	printable := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c >= 0x20 && c < 0x7f || c == '\t' || c == '\n' || c == '\r' {
			printable++
		}
	}
	return printable*4 >= len(b)*3
}
