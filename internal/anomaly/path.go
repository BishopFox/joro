package anomaly

import (
	"regexp"
	"strings"
)

var (
	numSegRe  = regexp.MustCompile(`^\d+$`)
	uuidSegRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSegRe  = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	opaqueRe  = regexp.MustCompile(`^[A-Za-z0-9_\-]+$`)
	digitRe   = regexp.MustCompile(`\d`)
)

// normalizePath folds volatile path segments to {id} so that /users/1 and
// /users/2 collapse to a single endpoint. Without it every record with an
// embedded identifier is its own endpoint and no per-endpoint baseline forms.
func normalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		segs[i] = normalizeSeg(s)
	}
	return strings.Join(segs, "/")
}

func normalizeSeg(s string) string {
	switch {
	case numSegRe.MatchString(s):
		return "{id}"
	case uuidSegRe.MatchString(s):
		return "{id}"
	case hexSegRe.MatchString(s):
		return "{id}"
	case len(s) >= 24 && opaqueRe.MatchString(s) && digitRe.MatchString(s):
		// A long token carrying both letters and digits: a session id, a signed
		// value, a slug with an embedded id. Opaque enough to template.
		return "{id}"
	}
	return s
}

// pathExt returns the lowercase file extension of the last path segment, or ""
// when there is none. It reads the raw path, not the templated one, so a
// templated trailing segment ({id}) yields no extension.
func pathExt(p string) string {
	if p == "" {
		return ""
	}
	seg := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		seg = p[i+1:]
	}
	dot := strings.LastIndexByte(seg, '.')
	if dot <= 0 || dot == len(seg)-1 {
		return ""
	}
	ext := strings.ToLower(seg[dot+1:])
	if len(ext) > 8 || !opaqueRe.MatchString(ext) {
		return ""
	}
	return ext
}

// majorCT strips parameters from a Content-Type, leaving "type/subtype".
func majorCT(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

// statusClass maps a status code to its hundreds band (2, 3, 4, 5), or 0.
func statusClass(code int) int {
	if code < 100 || code >= 600 {
		return 0
	}
	return code / 100
}

// commonWebExt are extensions ordinary enough that their rarity on a host is not
// interesting. A rare extension outside this set (.bak, .sql, .old, .zip) is.
var commonWebExt = map[string]struct{}{
	"html": {}, "htm": {}, "php": {}, "asp": {}, "aspx": {}, "jsp": {},
	"js": {}, "css": {}, "json": {}, "xml": {}, "txt": {}, "svg": {},
	"png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "webp": {}, "ico": {},
	"woff": {}, "woff2": {}, "ttf": {}, "map": {},
}
