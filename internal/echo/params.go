package echo

import (
	"bytes"
	"encoding/json"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/detect"
)

// boringHeaders are request headers whose values are either fixed by the client
// or echoed by every page on the host. Walking them buries the map in matches
// no operator sent.
var boringHeaders = map[string]bool{
	"Host": true, "Connection": true, "Content-Length": true,
	"Content-Type": true, "Accept": true, "Accept-Encoding": true,
	"Accept-Language": true, "Accept-Charset": true, "Cache-Control": true,
	"Pragma": true, "Upgrade-Insecure-Requests": true, "Te": true,
	"Sec-Fetch-Dest": true, "Sec-Fetch-Mode": true, "Sec-Fetch-Site": true,
	"Sec-Fetch-User": true, "Sec-Ch-Ua": true, "Sec-Ch-Ua-Mobile": true,
	"Sec-Ch-Ua-Platform": true, "Dnt": true, "Priority": true,
	"Cookie": true, // walked separately, per cookie
}

// ubiquitous are values so common that a match against one says nothing about
// the request that carried it.
var ubiquitous = map[string]bool{
	"true": true, "false": true, "null": true, "none": true, "undefined": true,
	"nil": true, "yes": true, "no": true, "on": true, "off": true,
	"all": true, "any": true, "default": true, "auto": true, "utf-8": true,
	"application/json": true, "text/html": true, "en": true, "en-us": true,
}

// Walk enumerates every value the request sent, in a stable order. Values are
// returned whether or not they pass the admission bar, because the count of
// inputs considered is worth reporting even when few are searched.
func Walk(m *detect.Message, cfg Config) []Value {
	var out []Value
	add := func(v Value) {
		if len(out) < cfg.MaxValuesPerRequest {
			out = append(out, v)
		}
	}

	if m.URL != nil {
		walkQuery(m.URL.RawQuery, SourceQuery, m.ReqRawHdr, hdrBase, add)
		walkPath(m.URL.EscapedPath(), m.ReqRawHdr, add)
	}
	walkBody(m, cfg, add)

	if cfg.ScanHeaders {
		walkCookies(m, add)
		for name, vals := range m.ReqHeader {
			if boringHeaders[name] {
				continue
			}
			for _, v := range vals {
				add(Value{
					Source: SourceHeader, Name: name, Value: v,
					Span: locate(m.ReqRawHdr, []byte(v), hdrBase),
				})
			}
		}
	}
	return out
}

// hdrBase is the offset of a header block within its raw document: a header
// block always starts at byte 0, so a header-relative offset is already a
// document offset.
const hdrBase = 0

// walkBody dispatches on content type. A body Parse did not populate — which is
// every body when detect's ScanRequests is off — yields nothing, which is why
// the engine parses with its own config.
func walkBody(m *detect.Message, cfg Config, add func(Value)) {
	if len(m.ReqBody) == 0 {
		return
	}
	ct, params, _ := mime.ParseMediaType(m.ReqHeader.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "json"):
		walkJSONBody(m.ReqBody, m.ReqBodyStart, add)
	case ct == "multipart/form-data":
		walkMultipart(m.ReqBody, params["boundary"], add)
	case ct == "application/x-www-form-urlencoded" || ct == "":
		walkQuery(string(m.ReqBody), SourceForm, m.ReqBody, m.ReqBodyStart, add)
	default:
		// An unrecognized body is still worth one whole-body needle when it is
		// small enough to be a single value rather than a document.
		if len(m.ReqBody) <= 512 {
			add(Value{
				Source: SourceForm, Name: "body", Value: string(m.ReqBody),
				Span: Span{Start: m.ReqBodyStart, End: m.ReqBodyStart + len(m.ReqBody)},
			})
		}
	}
}

// walkQuery splits an &-separated key=value list. It is used for both the URL
// query and a urlencoded body, which share a grammar including + for space.
func walkQuery(raw string, src Source, doc []byte, base int, add func(Value)) {
	if raw == "" {
		return
	}
	for _, pair := range strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		if pair == "" {
			continue
		}
		name, rawVal, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		val := percentDecode(rawVal, true)
		if val == "" {
			continue
		}
		add(Value{
			Source: src,
			Name:   percentDecode(name, true),
			Value:  val,
			Span:   locate(doc, []byte(rawVal), base),
		})
	}
}

// walkPath yields each non-empty path segment, named by its index. A segment is
// as much an input as a query parameter and is the one an application is most
// likely to render back as a title or an error.
func walkPath(escaped string, doc []byte, add func(Value)) {
	segs := strings.Split(escaped, "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		val := percentDecode(seg, false)
		if val == "" {
			continue
		}
		add(Value{
			Source: SourcePath,
			Name:   "[" + strconv.Itoa(i) + "]",
			Value:  val,
			Span:   locate(doc, []byte(seg), hdrBase),
		})
	}
}

// walkCookies splits the Cookie header into its pairs.
func walkCookies(m *detect.Message, add func(Value)) {
	for _, line := range m.ReqHeader.Values("Cookie") {
		for _, pair := range strings.Split(line, ";") {
			name, val, found := strings.Cut(strings.TrimSpace(pair), "=")
			if !found || val == "" {
				continue
			}
			add(Value{
				Source: SourceCookie, Name: name, Value: val,
				Span: locate(m.ReqRawHdr, []byte(val), hdrBase),
			})
		}
	}
}

// walkJSONBody visits every scalar leaf of a JSON body, naming it by a dotted
// path with [i] indices. Spans come from locating the leaf's encoded form,
// because decoding through encoding/json discards offsets.
func walkJSONBody(body []byte, base int, add func(Value)) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return
	}
	walkJSONValue(v, "", func(path, val string) {
		if val == "" {
			return
		}
		enc, err := json.Marshal(val)
		span := Span{}
		if err == nil && len(enc) >= 2 {
			span = locate(body, enc[1:len(enc)-1], base)
		}
		add(Value{Source: SourceJSON, Name: path, Value: val, Span: span})
	})
}

// walkJSONValue recurses into objects and arrays, reporting scalars. Numbers
// are formatted without exponent notation so a large integer keeps the digits
// the application sent.
func walkJSONValue(v any, path string, fn func(path, val string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walkJSONValue(sub, p, fn)
		}
	case []any:
		for i, sub := range t {
			walkJSONValue(sub, path+"["+strconv.Itoa(i)+"]", fn)
		}
	case string:
		fn(path, t)
	case float64:
		fn(path, strconv.FormatFloat(t, 'f', -1, 64))
	case bool:
		fn(path, strconv.FormatBool(t))
	}
}

// walkMultipart yields each form field's value, skipping file parts: a file's
// bytes are a payload, not a parameter, and reading them defeats the body cap.
func walkMultipart(body []byte, boundary string, add func(Value)) {
	if boundary == "" {
		return
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		p, err := mr.NextPart()
		if err != nil {
			return
		}
		if p.FileName() != "" {
			p.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, _ := p.Read(buf)
		p.Close()
		if n <= 0 {
			continue
		}
		val := string(buf[:n])
		add(Value{
			Source: SourceMultipart, Name: p.FormName(), Value: val,
			Span: locate(body, buf[:n], 0),
		})
	}
}

// locate reports where needle sits in doc, but only when it occurs exactly
// once. An ambiguous literal gets no span rather than a guessed one, because a
// span pointing at the wrong occurrence reads as a fact.
func locate(doc, needle []byte, base int) Span {
	if len(needle) == 0 || len(doc) == 0 {
		return Span{}
	}
	i := bytes.Index(doc, needle)
	if i < 0 {
		return Span{}
	}
	if bytes.Index(doc[i+1:], needle) >= 0 {
		return Span{}
	}
	return Span{Start: base + i, End: base + i + len(needle)}
}

// percentDecode expands %XX in place, leaving a malformed escape as the literal
// bytes it is. url.QueryUnescape rejects the whole input on a single bare %,
// which is exactly the input this engine exists to look at. plus controls
// whether + means space, which is true of a query and a urlencoded body and
// false of a path segment.
func percentDecode(s string, plus bool) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case s[i] == '+' && plus:
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// admit reports whether a value is worth searching for. Short and ubiquitous
// values collide with ordinary page text often enough to bury every real
// reflection, so the bar is length, with an exception for anything carrying a
// metacharacter: a three-byte probe is short precisely because it is a probe.
func admit(v string, cfg Config) bool {
	if len(v) > maxNeedleLen {
		return false
	}
	if ubiquitous[strings.ToLower(v)] {
		return false
	}
	if strings.ContainsAny(v, metaChars) {
		return len(v) >= 3
	}
	if len(v) < cfg.MinValueLen {
		return false
	}
	// A bare number of any length is a counter, an id or a price, and matches
	// page text constantly.
	if isAllDigits(v) {
		return false
	}
	return true
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// maxNeedleLen caps a single needle. A value longer than this is a document
// being round-tripped, and matching it says nothing an operator can act on.
const maxNeedleLen = 4096
