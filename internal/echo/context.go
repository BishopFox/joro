package echo

import (
	"bytes"
	"sort"
	"strings"
)

// The context scanner answers what a browser would do with these bytes, not
// what the specification says they mean. That is why it is hand-rolled rather
// than built on x/net/html, which is already in the module graph: a conforming
// tree builder normalizes exactly the malformed markup an injection produces,
// does not expose byte offsets for attribute values, and recovers from errors
// by a different rule than the parser that will actually run the reflection.
//
// One pass produces a sorted, gapless span list; each reflection then binary
// searches it. Re-deriving the context per match would reparse the document
// once per reflection, and a page that reflects a value forty times is common.

// ctxSpan is one run of bytes sharing a syntactic position.
type ctxSpan struct {
	start, end int
	ctx        Context
	js         JSContext
	attr       string
	quote      string
	// valStart is where the enclosing attribute's value begins, so a reflection
	// can tell whether it controls the start of a URL.
	valStart int
}

// classify scans a response body into spans. ct is the simplified content-type
// keyword from detect.ContentTypeKeyword.
func classify(body []byte, ct string) []ctxSpan {
	switch ct {
	case "html", "xml":
		return classifyHTML(body)
	case "json":
		return classifyJSON(body)
	default:
		if looksHTML(body) {
			return classifyHTML(body)
		}
		return []ctxSpan{{start: 0, end: len(body), ctx: ContextPlain}}
	}
}

// looksHTML catches a document served as text/plain or with no type at all that
// a browser will still sniff and render.
func looksHTML(b []byte) bool {
	head := b
	if len(head) > 1024 {
		head = head[:1024]
	}
	l := bytes.ToLower(head)
	return bytes.Contains(l, []byte("<html")) || bytes.Contains(l, []byte("<!doctype html")) ||
		bytes.Contains(l, []byte("<body")) || bytes.Contains(l, []byte("<div"))
}

type spanWriter struct {
	spans []ctxSpan
	at    int
}

// emit closes the run ending at end. Adjacent runs sharing every attribute are
// merged, which keeps a page of plain text to a single span.
func (w *spanWriter) emit(end int, s ctxSpan) {
	if end <= w.at {
		return
	}
	s.start, s.end = w.at, end
	if n := len(w.spans); n > 0 {
		p := &w.spans[n-1]
		if p.end == s.start && p.ctx == s.ctx && p.js == s.js &&
			p.attr == s.attr && p.quote == s.quote && p.valStart == s.valStart {
			p.end = s.end
			w.at = end
			return
		}
	}
	w.spans = append(w.spans, s)
	w.at = end
}

func classifyHTML(b []byte) []ctxSpan {
	w := &spanWriter{}
	i := 0
	for i < len(b) {
		if b[i] != '<' {
			i++
			continue
		}
		// A '<' not followed by a name, '/', '!' or '?' is literal text to a
		// browser, so it is left in the text run.
		if i+1 >= len(b) || !startsMarkup(b[i+1]) {
			i++
			continue
		}
		w.emit(i, ctxSpan{ctx: ContextHTMLText})

		if bytes.HasPrefix(b[i:], []byte("<!--")) {
			end := bytes.Index(b[i+4:], []byte("-->"))
			if end < 0 {
				w.emit(len(b), ctxSpan{ctx: ContextHTMLComment})
				return w.spans
			}
			i = i + 4 + end + 3
			w.emit(i, ctxSpan{ctx: ContextHTMLComment})
			continue
		}
		if b[i+1] == '!' || b[i+1] == '?' {
			end := bytes.IndexByte(b[i:], '>')
			if end < 0 {
				w.emit(len(b), ctxSpan{ctx: ContextHTMLComment})
				return w.spans
			}
			i += end + 1
			w.emit(i, ctxSpan{ctx: ContextHTMLComment})
			continue
		}

		j := i + 1
		closing := false
		if j < len(b) && b[j] == '/' {
			j++
			closing = true
		}
		nameStart := j
		for j < len(b) && isNameByte(b[j]) {
			j++
		}
		name := strings.ToLower(string(b[nameStart:j]))
		w.emit(j, ctxSpan{ctx: ContextTagName})

		j = scanAttrs(b, j, w)
		i = j

		// A raw-text element's content is not markup; everything up to its own
		// end tag belongs to the element, including any '<' inside it. Only an
		// opening tag enters that mode: the element's own end tag carries the
		// same name, and treating it as an opening one would swallow the rest
		// of the document.
		if !closing && (name == "script" || name == "style") {
			closeAt := findRawTextEnd(b, i, name)
			if name == "script" {
				scanJS(b, i, closeAt, w)
			} else {
				w.emit(closeAt, ctxSpan{ctx: ContextStyle})
			}
			i = closeAt
		}
	}
	w.emit(len(b), ctxSpan{ctx: ContextHTMLText})
	return w.spans
}

func startsMarkup(c byte) bool {
	return c == '/' || c == '!' || c == '?' ||
		c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '-' || c == '_' || c == ':' || c == '.'
}

// scanAttrs walks a tag's attribute list from just past the tag name, returning
// the offset just past the closing '>'.
func scanAttrs(b []byte, i int, w *spanWriter) int {
	for i < len(b) {
		for i < len(b) && isSpace(b[i]) {
			i++
		}
		if i >= len(b) {
			break
		}
		if b[i] == '>' {
			i++
			w.emit(i, ctxSpan{ctx: ContextTagName})
			return i
		}
		if b[i] == '/' {
			i++
			continue
		}
		nameStart := i
		for i < len(b) && !isSpace(b[i]) && b[i] != '=' && b[i] != '>' {
			i++
		}
		attr := strings.ToLower(string(b[nameStart:i]))
		w.emit(i, ctxSpan{ctx: ContextAttrName})

		for i < len(b) && isSpace(b[i]) {
			i++
		}
		if i >= len(b) || b[i] != '=' {
			continue
		}
		i++ // '='
		for i < len(b) && isSpace(b[i]) {
			i++
		}
		if i >= len(b) {
			break
		}
		w.emit(i, ctxSpan{ctx: ContextAttrName})

		quote := ""
		if b[i] == '"' || b[i] == '\'' {
			quote = string(b[i])
			i++
			w.emit(i, ctxSpan{ctx: ContextAttrName})
			valStart := i
			end := bytes.IndexByte(b[i:], quote[0])
			if end < 0 {
				w.emit(len(b), ctxSpan{ctx: ContextAttrValue, attr: attr, quote: quote, valStart: valStart})
				return len(b)
			}
			i += end
			w.emit(i, ctxSpan{ctx: ContextAttrValue, attr: attr, quote: quote, valStart: valStart})
			i++ // closing quote
			w.emit(i, ctxSpan{ctx: ContextAttrName})
			continue
		}
		valStart := i
		for i < len(b) && !isSpace(b[i]) && b[i] != '>' {
			i++
		}
		w.emit(i, ctxSpan{ctx: ContextAttrValue, attr: attr, valStart: valStart})
	}
	w.emit(len(b), ctxSpan{ctx: ContextTagName})
	return len(b)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// findRawTextEnd locates the element's end tag. A browser closes a raw-text
// element on the first case-insensitive "</name" regardless of what precedes
// it, including inside a string literal, which is why a reflection that can
// write "</script" escapes the block whatever the JavaScript around it says.
func findRawTextEnd(b []byte, from int, name string) int {
	needle := []byte("</" + name)
	for i := from; i < len(b); i++ {
		if b[i] != '<' {
			continue
		}
		if i+len(needle) <= len(b) && bytes.EqualFold(b[i:i+len(needle)], needle) {
			return i
		}
	}
	return len(b)
}

// scanJS sub-classifies a script block. Regular-expression literals are read as
// code: telling one from a division needs the preceding token's grammar, and
// guessing wrong would mislabel ordinary arithmetic as a literal.
func scanJS(b []byte, from, to int, w *spanWriter) {
	i := from
	for i < to {
		c := b[i]
		switch {
		case c == '/' && i+1 < to && b[i+1] == '/':
			w.emit(i, ctxSpan{ctx: ContextScript, js: JSCode})
			end := bytes.IndexByte(b[i:to], '\n')
			if end < 0 {
				i = to
			} else {
				i += end
			}
			w.emit(i, ctxSpan{ctx: ContextScript, js: JSComment})

		case c == '/' && i+1 < to && b[i+1] == '*':
			w.emit(i, ctxSpan{ctx: ContextScript, js: JSCode})
			end := bytes.Index(b[i+2:to], []byte("*/"))
			if end < 0 {
				i = to
			} else {
				i = i + 2 + end + 2
			}
			w.emit(i, ctxSpan{ctx: ContextScript, js: JSComment})

		case c == '"' || c == '\'' || c == '`':
			w.emit(i+1, ctxSpan{ctx: ContextScript, js: JSCode})
			js := JSStringDouble
			switch c {
			case '\'':
				js = JSStringSingle
			case '`':
				js = JSTemplate
			}
			i = scanJSString(b, i+1, to, c)
			w.emit(i, ctxSpan{ctx: ContextScript, js: js})
			if i < to {
				i++
				w.emit(i, ctxSpan{ctx: ContextScript, js: JSCode})
			}

		default:
			i++
		}
	}
	w.emit(to, ctxSpan{ctx: ContextScript, js: JSCode})
}

// scanJSString returns the offset of the closing delimiter, or to.
func scanJSString(b []byte, i, to int, quote byte) int {
	for i < to {
		switch b[i] {
		case '\\':
			i += 2
			continue
		case quote:
			return i
		case '\n':
			// An unterminated single- or double-quoted literal ends at the
			// newline; a template literal spans lines.
			if quote != '`' {
				return i
			}
		}
		i++
	}
	return to
}

// classifyJSON marks string values and keys. A key is a string whose next
// non-space byte is a colon.
func classifyJSON(b []byte) []ctxSpan {
	w := &spanWriter{}
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		w.emit(i+1, ctxSpan{ctx: ContextPlain})
		end := scanJSString(b, i+1, len(b), '"')
		j := end + 1
		for j < len(b) && isSpace(b[j]) {
			j++
		}
		ctx := ContextJSONString
		if j < len(b) && b[j] == ':' {
			ctx = ContextJSONKey
		}
		w.emit(end, ctxSpan{ctx: ctx})
		i = end
		w.emit(i+1, ctxSpan{ctx: ContextPlain})
	}
	w.emit(len(b), ctxSpan{ctx: ContextPlain})
	return w.spans
}

// sinkAt finds the span covering off. The spans are gapless and sorted, so this
// is a binary search rather than a walk.
func sinkAt(spans []ctxSpan, off int) sink {
	if len(spans) == 0 {
		return sink{ctx: ContextPlain}
	}
	i := sort.Search(len(spans), func(k int) bool { return spans[k].end > off })
	if i >= len(spans) {
		i = len(spans) - 1
	}
	// A reflection starting on the '<' that opens a tag is the reflection that
	// created that tag. Reporting the tag it became describes the payload; the
	// operator needs the position it was injected into, which is the run before.
	if i > 0 && spans[i].ctx == ContextTagName && off == spans[i].start {
		i--
	}
	s := spans[i]
	return sink{
		ctx: s.ctx, js: s.js, attr: s.attr, quote: s.quote,
		atValueStart: s.ctx == ContextAttrValue && off == s.valStart,
	}
}
