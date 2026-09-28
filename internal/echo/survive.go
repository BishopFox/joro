package echo

import (
	"strings"

	"github.com/BishopFox/joro/internal/detect"
)

// metaChars are the characters whose survival changes what a reflection can do.
// Whitespace is deliberately absent: it survives almost everything and would
// make the admission rule in params.go accept every short value there is. The
// one context where a space matters, an unquoted attribute, tests for it
// directly.
const metaChars = "<>\"'`&\\/(){};=\n\r"

// eventAttrs are attributes whose value is script. A reflection inside one is
// already in code and needs no quote to escape.
func isEventAttr(name string) bool {
	return len(name) > 2 && (name[0] == 'o' || name[0] == 'O') &&
		(name[1] == 'n' || name[1] == 'N')
}

// urlAttrs are attributes a browser will navigate or fetch, where controlling
// the start of the value is enough without any metacharacter surviving.
var urlAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true,
	"data": true, "poster": true, "srcdoc": true, "xlink:href": true,
	"background": true, "cite": true, "longdesc": true, "manifest": true,
}

// survivedChars reports which of the value's metacharacters reached the
// response literally, by asking the view's offset map how many source bytes
// produced each decoded byte. One source byte that equals the decoded byte
// passed through untouched; anything wider was an escape.
//
// Reading survival off the offset map rather than off the raw slice is what
// keeps an encoding's own punctuation out of the answer: the '&' in "&lt;" is a
// byte of the escape, not a '&' the application let through.
func survivedChars(v view, start, end int) string {
	var seen [256]bool
	var out []byte
	for k := start; k < end && k < len(v.b); k++ {
		c := v.b[k]
		if strings.IndexByte(metaChars, c) < 0 {
			continue
		}
		if v.at(k+1)-v.at(k) != 1 {
			continue
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return string(out)
}

// sink is the placement of one reflection, everything the breakout rubric needs.
type sink struct {
	ctx   Context
	js    JSContext
	attr  string
	quote string
	// atValueStart marks a reflection that begins its attribute's value, which
	// is what decides whether a URL attribute can be given a new scheme.
	atValueStart bool
}

// breakout reports whether what survived is enough to leave the sink. The rubric
// is per context because the escape differs: a quoted attribute needs its own
// quote, a script string needs its delimiter or the closing tag, and a response
// header needs a line break.
func breakout(s sink, survived string) bool {
	has := func(cs string) bool { return strings.ContainsAny(survived, cs) }

	// Closing the enclosing element escapes any HTML context, whatever else the
	// sink is, so it is checked before the per-context rules.
	if has("<") && has("/") {
		switch s.ctx {
		case ContextScript, ContextStyle, ContextHTMLComment:
			return true
		}
	}

	switch s.ctx {
	case ContextHTMLText, ContextPlain:
		return has("<")

	case ContextHTMLComment:
		return has("<>")

	case ContextTagName, ContextAttrName:
		return has(">") || has("=") || has("\"'")

	case ContextAttrValue:
		switch {
		case s.quote == `"`:
			if has(`"`) {
				return true
			}
		case s.quote == `'`:
			if has(`'`) {
				return true
			}
		default:
			// Unquoted: any delimiter ends the value and starts a new attribute.
			if has(">") || has("\"'`=") {
				return true
			}
		}
		if isEventAttr(s.attr) {
			// Already script; a quote or a parenthesis is enough to add a call.
			return has("\"'();")
		}
		if urlAttrs[strings.ToLower(s.attr)] && s.atValueStart {
			// Controlling the scheme does not need a metacharacter to survive.
			return true
		}
		return false

	case ContextScript:
		switch s.js {
		case JSStringDouble:
			return has(`"`) || has("\n\r")
		case JSStringSingle:
			return has("'") || has("\n\r")
		case JSTemplate:
			return has("`") || has("{")
		case JSComment:
			return has("\n\r")
		default:
			// Reflected into code: any structural character is enough.
			return has("\"'`();{}=")
		}

	case ContextStyle:
		return has("{};")

	case ContextJSONString, ContextJSONKey:
		return has(`"`)

	case ContextHeaderValue:
		return has("\n\r")
	}
	return false
}

// confidence rates how likely a match is a real reflection rather than an
// accident of page text. Length and entropy are the whole signal: a long or
// high-entropy value the operator sent is not in the response by chance, and a
// short dictionary word usually is.
func confidence(value string) Confidence {
	switch {
	case len(value) >= 16 || detect.ShannonEntropy(value) >= 3.5:
		return ConfidenceHigh
	case len(value) >= 8 || strings.ContainsAny(value, metaChars):
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}
