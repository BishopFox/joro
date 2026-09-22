package apispec

import "strings"

// destructiveWords are the verbs that suggest an operation changes something the
// operator would not want changed on a live target. Ported from sj, whose
// judgement here is sound: an API scanner that silently issues POST /purchase is
// a liability, and the cost of asking first is one click.
var destructiveWords = []string{
	"add", "block", "build", "buy", "cancel", "change", "clear", "create", "delete",
	"deploy", "destroy", "disable", "drop", "edit", "emergency", "erase", "execute",
	"insert", "kill", "modify", "order", "overwrite", "pause", "purchase", "purge",
	"rebuild", "remove", "replace", "reset", "restart", "revoke", "run", "sell",
	"send", "set", "shutdown", "start", "stop", "terminate", "truncate", "update",
	"upload", "wipe", "write",
}

// destructiveMethods are methods whose semantics are destructive regardless of
// what the path is called.
var destructiveMethods = map[string]string{
	"DELETE": "DELETE removes the addressed resource",
	"PATCH":  "PATCH modifies the addressed resource",
}

// Classify reports whether an operation looks destructive, and why.
//
// It is advisory: it never blocks a render, only a send, and the caller decides
// whether to honor it. Two differences from sj matter.
//
// First, this runs at parse time over the method, path, operationId and summary.
// sj checks the interpolated URL at send time, reading u.RawPath + "?" +
// u.RawQuery — and RawPath is empty for any URL that needed no escaping, so on
// most targets the gate inspects only the query string and never fires at all.
//
// Second, sj drops DELETE and PATCH operations during parsing, so they are
// invisible. Reporting them instead means the operator can see the whole API
// surface and tick the one they meant to test.
func Classify(method, path, opID, summary string, whitelist []string) (bool, []string) {
	var reasons []string

	method = strings.ToUpper(method)
	if reason, ok := destructiveMethods[method]; ok {
		reasons = append(reasons, reason)
	}

	skip := make(map[string]bool, len(whitelist))
	for _, w := range whitelist {
		skip[strings.ToLower(strings.TrimSpace(w))] = true
	}

	haystack := splitWords(path + " " + opID + " " + summary)
	for _, word := range destructiveWords {
		if skip[word] {
			continue
		}
		if containsWord(haystack, word) {
			reasons = append(reasons, "mentions "+word)
		}
	}

	return len(reasons) > 0, reasons
}

// containsWord matches a keyword against one end of an identifier, so "orders"
// and "reorder" both match "order" while "borders" does not. A plain substring
// test — which is what sj does — flags every path containing "border", "asset"
// (set) and similar, and an operator who learns the gate cries wolf will disable
// it.
//
// One boundary, not two: "orders" and "createOrder" are how this operation is
// ordinarily spelled, and both put a letter against one side. The cost is that a
// bare "border" reads as "order" — no boundary rule separates it from "reorder"
// — and the failures are not equal: a false positive costs a click, a false
// negative sends a live POST to a payment endpoint.
func containsWord(haystack, word string) bool {
	for i := 0; ; {
		idx := strings.Index(haystack[i:], word)
		if idx < 0 {
			return false
		}
		start := i + idx
		end := start + len(word)
		if !isWordByte(haystack, start-1) || !isWordByte(haystack, end) {
			return true
		}
		i = start + 1
		if i >= len(haystack) {
			return false
		}
	}
}

// splitWords lowercases the haystack, breaking camelCase and separators apart.
//
// Without it "createOrder" is one token "createorder", where both keywords have
// a letter on each side and neither matches — and operationId is the field most
// likely to name the verb.
func splitWords(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			// Split at the "O" of createOrder, not inside the "URL" of parseURL.
			if i > 0 && isLowerOrDigit(s[i-1]) {
				b.WriteByte(' ')
			}
			b.WriteByte(c + 32)
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func isLowerOrDigit(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// isWordByte reports whether the byte at i continues an identifier. Out-of-range
// counts as a boundary.
func isWordByte(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// DefaultMethods is the method whitelist a run starts with: everything except
// the two whose semantics are destructive on their own.
func DefaultMethods() []string {
	return []string{"GET", "POST", "PUT", "HEAD", "OPTIONS", "TRACE"}
}
