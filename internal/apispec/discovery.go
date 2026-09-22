package apispec

import (
	"net/url"
	"regexp"
	"strings"
)

// CandidateSet selects how wide a discovery sweep goes.
type CandidateSet string

const (
	// CandidatePriority is the 87-path list tried directly. This is the default,
	// and the reason is not politeness: every candidate is sent through Joro's
	// own proxy and therefore occupies a row in the capture store, which is a
	// ring buffer. A full sweep is thousands of rows and can evict the
	// operator's real traffic — the one place where routing through the proxy,
	// otherwise the whole point, costs something.
	CandidatePriority CandidateSet = "priority"

	// CandidateFull crosses every prefix with every endpoint name. Thousands of
	// requests; offer it with the eviction consequence stated.
	CandidateFull CandidateSet = "full"
)

// CandidatePaths builds the ordered candidate list for a sweep.
//
// Order matters and is sj's: HTML UI pages first, because one hit there names
// the document directly and makes the rest of the sweep unnecessary; then the
// priority paths; then the JavaScript bundles; then the JSON names in three
// suffix forms. Duplicates are removed across the whole list, not just within
// each source.
func CandidatePaths(basePath string, set CandidateSet) []string {
	base := normalizeBasePath(basePath)

	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	cross := func(endpoints []string, suffix string) {
		for _, dir := range prefixDirs {
			for _, ep := range endpoints {
				if dir == "" && ep == "" {
					continue
				}
				add(base + dir + ep + suffix)
			}
		}
	}

	for _, ep := range htmlEndpoints {
		add(base + ep + ".html")
	}
	for _, p := range priorityURLs {
		add(base + p)
	}
	if set != CandidateFull {
		return out
	}

	cross(htmlEndpoints, ".html")
	cross(javascriptEndpoints, ".js")
	cross(jsonEndpoints, "")
	cross(jsonEndpoints, ".json")
	cross(jsonEndpoints, "/")
	return out
}

// BodyKind is what a discovery response turned out to be.
type BodyKind string

const (
	KindSpec      BodyKind = "spec"      // parsed as a document with paths
	KindWeak      BodyKind = "weak"      // looks document-shaped but did not parse
	KindReference BodyKind = "reference" // a page or script naming a document
	KindChallenge BodyKind = "challenge" // a WAF or bot-check interstitial
	KindSkip      BodyKind = "skip"      // binary or otherwise uninteresting
	KindNone      BodyKind = "none"
)

// skipContentTypes are types that cannot carry a document. Checking these first
// avoids running regexes over images and archives.
var skipContentTypes = []string{
	"image/", "video/", "audio/", "font/", "text/css",
	"application/zip", "application/pdf", "application/octet-stream",
}

// ShouldSkipContentType reports whether a response body is worth examining.
func ShouldSkipContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, skip := range skipContentTypes {
		if strings.Contains(ct, skip) {
			return true
		}
	}
	return false
}

// challengeMarkers are strings that appear in bot-check interstitials. A run
// that collects these is being answered by a WAF, and continuing wastes
// thousands of requests to learn nothing.
var challengeMarkers = []string{
	"cf-browser-verification", "cf_chl_opt", "cf-challenge", "__cf_chl",
	"just a moment...", "checking your browser", "ddos protection by",
	"attention required! | cloudflare", "please enable cookies",
	"access denied", "request unsuccessful. incapsula",
	"incapsula incident id", "_incapsula_resource",
}

// LooksLikeChallenge reports whether a body is a bot-check interstitial.
func LooksLikeChallenge(body []byte) bool {
	// Bound the scan: a challenge page is small and its markers are near the top.
	window := body
	if len(window) > 64<<10 {
		window = window[:64<<10]
	}
	lower := strings.ToLower(string(window))
	for _, marker := range challengeMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// LooksLikeHTMLDocument reports whether a body is an HTML page, for a response
// whose Content-Type lied or was absent.
func LooksLikeHTMLDocument(body []byte) bool {
	window := body
	if len(window) > 2048 {
		window = window[:2048]
	}
	lower := strings.ToLower(strings.TrimSpace(string(window)))
	return strings.HasPrefix(lower, "<!doctype html") ||
		strings.HasPrefix(lower, "<html") ||
		strings.Contains(lower, "<head")
}

var (
	// specKeyRe matches a "url:" / "configUrl:" / "specUrl:" assignment, which is
	// how a Swagger UI page names the document it loads.
	specKeyRe = regexp.MustCompile(`(?i)"?(?:config|spec)?url"?\s*:\s*["']([^"']+)["']`)
	// specAttrRe matches a spec-url attribute or a plain href/src.
	specAttrRe = regexp.MustCompile(`(?i)(?:spec-url|data-url|href|src)\s*=\s*["']([^"']+)["']`)
	// discoveryPathsRe matches Swashbuckle's discoveryPaths initializer.
	discoveryPathsRe = regexp.MustCompile(`(?i)discoveryPaths\s*:\s*arrayFrom\(\s*['"]([^'"]+)['"]`)

	// specTokenRe finds a URL-shaped token anywhere in a body, quoted or not.
	//
	// The targeted patterns above only fire on `url: "literal"`. A Swagger UI
	// initializer frequently computes the value instead — petstore3's picks it
	// out of a host-to-URL table held in a template literal and assigns
	// `url: definitionURL` — so the document is plainly present in the file and
	// none of the key/attribute regexes can see it. Matching URL shapes and
	// letting LooksLikeSpecReference and the caller's same-host rule do the
	// filtering catches those without loosening either.
	specTokenRe = regexp.MustCompile(`(?i)(https?://[^\s"'` + "`" + `,;()<>]+|/[A-Za-z0-9_./~-]*(?:openapi|swagger|api-docs|apispec)[A-Za-z0-9_./~-]*)`)
)

// uiBundleNames are Swagger UI's own scripts. They are libraries, not
// initializers, so there is no point scanning them for an embedded document.
var uiBundleNames = []string{
	"swagger-ui-bundle", "swagger-ui-standalone-preset", "swagger-ui-es-bundle",
	"swagger-ui-es-bundle-core", "swagger-ui-layout", "swagger-ui-plugins",
	"swagger-ui.min", "swagger-ui.js", "swagger-ui.css",
}

// LooksLikeSwaggerInit reports whether a script URL is worth reading for an
// embedded document, as opposed to being one of Swagger UI's own bundles.
func LooksLikeSwaggerInit(rawURL string) bool {
	path := strings.ToLower(urlPath(rawURL))
	if !strings.HasSuffix(path, ".js") {
		return false
	}
	for _, bundle := range uiBundleNames {
		if strings.Contains(path, bundle) {
			return false
		}
	}
	return true
}

// LooksLikeSpecReference filters extracted references down to ones that could
// name a document, so a sweep does not chase every stylesheet on a page.
func LooksLikeSpecReference(ref string) bool {
	lower := strings.ToLower(ref)
	if lower == "" || strings.HasPrefix(lower, "#") || strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "mailto:") {
		return false
	}
	for _, ext := range []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"} {
		if strings.HasSuffix(urlPath(lower), ext) {
			return false
		}
	}
	for _, bundle := range uiBundleNames {
		if strings.Contains(lower, bundle) {
			return false
		}
	}
	for _, hint := range []string{"api-docs", "openapi", "swagger.json", "swagger.yaml", "swagger.yml", "api-json", "swagger-resources", "apispec"} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	p := urlPath(lower)
	for _, ext := range []string{".json", ".yaml", ".yml", "-json", "_json"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return strings.HasSuffix(p, ".js")
}

// ExtractSpecRefs pulls candidate document URLs out of an HTML page or a
// JavaScript initializer, resolved against the page they came from.
//
// Resolution deliberately returns absolute URLs so the caller can enforce that a
// reference stays on the run's own host. sj follows any absolute reference it
// finds, which lets a page a target controls redirect the sweep onto a third
// party — a scope escape, and one the operator never asked for.
func ExtractSpecRefs(body []byte, pageURL string) []string {
	window := body
	if len(window) > 512<<10 {
		window = window[:512<<10]
	}
	text := string(window)

	seen := map[string]bool{}
	var out []string
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if !LooksLikeSpecReference(ref) {
			return
		}
		abs := resolveRefURL(pageURL, ref)
		if abs == "" || seen[abs] {
			return
		}
		seen[abs] = true
		out = append(out, abs)
	}

	// Targeted patterns first, so a document the page names explicitly is
	// followed before anything merely URL-shaped.
	for _, re := range []*regexp.Regexp{specKeyRe, discoveryPathsRe, specAttrRe} {
		for _, m := range re.FindAllStringSubmatch(text, 64) {
			if len(m) > 1 {
				add(m[1])
			}
		}
	}
	for _, m := range specTokenRe.FindAllStringSubmatch(text, 128) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	return out
}

// resolveRefURL resolves a possibly-relative reference against the page URL.
func resolveRefURL(pageURL, ref string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(u)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	resolved.Fragment = ""
	return resolved.String()
}

// SameHost reports whether a discovered reference stays on the run's target.
func SameHost(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Host, ub.Host)
}

func urlPath(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return u.Path
	}
	if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}
