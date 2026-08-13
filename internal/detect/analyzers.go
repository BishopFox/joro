package detect

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// AnalyzerHit is one result emitted by an analyzer. Empty Severity and
// Confidence inherit the rule's own values; an analyzer sets them only to
// escalate or downgrade a specific case.
type AnalyzerHit struct {
	Detail     string
	Evidence   string
	Severity   Severity
	Confidence Confidence
	// GroupExtra adds a dimension to the dedupe key, e.g. a cookie name for a
	// per-cookie rule.
	GroupExtra string
	// Offset is relative to the buffer named by OffsetIn, not to the raw document;
	// newFinding translates it. An unset OffsetIn means no offset.
	Offset   int
	OffsetIn Target
	// OffsetLen is the length of the matched region at Offset, which is not
	// len(Evidence): an analyzer's Evidence is a synthesized description, not the
	// matched bytes. Zero means no usable region, and the finding reports no
	// offset.
	OffsetLen int
	Part      string

	// rawMatch is the unredacted matched value, set only by the regex path. Hashed
	// into the dedupe key and used as the redaction basis; never stored on the
	// resulting Finding.
	rawMatch string
}

// Analyzer inspects a whole message and emits zero or more hits, covering the
// checks a regex cannot express: the absence of a header, a relationship between
// request and response headers, or a decision requiring a parsed value.
type Analyzer func(m *Message, emit func(AnalyzerHit))

// analyzerRegistry maps Rule.Analyzer names to implementations. An analyzer is a
// rule whose behavior lives in code; it appears in the same rules list and
// inherits enable/disable, severity override, and grouping.
var analyzerRegistry = map[string]Analyzer{
	"missingHSTS":                 anMissingHSTS,
	"weakHSTS":                    anWeakHSTS,
	"missingCSP":                  anMissingCSP,
	"cspReportOnly":               anCSPReportOnly,
	"cspUnsafeInline":             anCSPUnsafeInline,
	"cspUnsafeEval":               anCSPUnsafeEval,
	"cspWildcardScript":           anCSPWildcardScript,
	"missingFrameOptions":         anMissingFrameOptions,
	"invalidFrameOptions":         anInvalidFrameOptions,
	"missingContentTypeOptions":   anMissingContentTypeOptions,
	"xssProtectionDisabled":       anXSSProtectionDisabled,
	"corsWildcard":                anCORSWildcard,
	"corsReflectedWithCreds":      anCORSReflectedWithCreds,
	"corsNullOrigin":              anCORSNullOrigin,
	"corsCredsWithWildcard":       anCORSCredsWithWildcard,
	"insecureRedirect":            anInsecureRedirect,
	"insecureTransportHTML":       anInsecureTransportHTML,
	"mixedContent":                anMixedContent,
	"cacheControlAuthenticated":   anCacheControlAuthenticated,
	"cookieMissingSecure":         anCookieMissingSecure,
	"cookieSetOverHTTP":           anCookieSetOverHTTP,
	"cookieMissingHTTPOnly":       anCookieMissingHTTPOnly,
	"cookieMissingSameSite":       anCookieMissingSameSite,
	"cookieSameSiteNoneInsecure":  anCookieSameSiteNoneInsecure,
	"cookieOverbroadDomain":       anCookieOverbroadDomain,
	"cookieJWTValue":              anCookieJWTValue,
	"basicAuthHeader":             anBasicAuthHeader,
	"jwtAlgNone":                  anJWTAlgNone,
	"jwtSensitiveClaims":          anJWTSensitiveClaims,
	"loginForm":                   anLoginForm,
	"loginFormOverHTTP":           anLoginFormOverHTTP,
	"loginFormCrossOrigin":        anLoginFormCrossOrigin,
	"passwordSubmittedOverHTTP":   anPasswordSubmittedOverHTTP,
	"dotenvDump":                  anDotenvDump,
	"piiBulkExposure":             anPIIBulkExposure,
	"awsKeyPair":                  anAWSKeyPair,
	"kubeconfigOrCloudCredential": anKubeconfigOrCloudCredential,
}

// analyzerRules declares the rule records that bind analyzer functions into the
// library. These group per host unless the check is genuinely per-URL.
func analyzerRules() []Rule {
	an := func(id, name, fn string, cat Category, sev Severity, desc string) Rule {
		return Rule{
			ID: id, Name: name, Kind: KindAnalyzer, Analyzer: fn,
			Category: cat, Severity: sev, Target: TargetMessage,
			GroupBy: GroupByHost, Description: desc,
		}
	}
	perURL := func(r Rule) Rule { r.GroupBy = GroupByURL; return r }

	return []Rule{
		// Transport security.
		an("missing-hsts", "Strict-Transport-Security missing", "missingHSTS",
			CategoryHeaders, SeverityInfo,
			"No HSTS header on an HTTPS response. Deliberately not reported for plain HTTP responses, where the header is ignored by browsers and flagging it would be incorrect."),
		an("weak-hsts-max-age", "Strict-Transport-Security max-age too low", "weakHSTS",
			CategoryHeaders, SeverityInfo,
			"HSTS present but max-age is below 180 days, or zero, which disables the protection."),
		// Content Security Policy.
		an("missing-csp", "Content-Security-Policy missing", "missingCSP",
			CategoryHeaders, SeverityInfo,
			"No enforced or report-only CSP on an HTML document. Not evaluated for JSON, JavaScript, CSS, or images, where a CSP has no effect."),
		an("csp-report-only-only", "Content-Security-Policy is report-only", "cspReportOnly",
			CategoryHeaders, SeverityInfo,
			"Only the report-only variant is present, so the policy is monitored but never enforced."),
		an("csp-unsafe-inline-script", "CSP allows unsafe-inline scripts", "cspUnsafeInline",
			CategoryHeaders, SeverityInfo,
			"The effective script-src allows unsafe-inline with no nonce or hash present. Not reported when a nonce or hash is present, because CSP3 browsers ignore unsafe-inline in that case."),
		an("csp-unsafe-eval", "CSP allows unsafe-eval", "cspUnsafeEval",
			CategoryHeaders, SeverityInfo,
			"The effective script-src allows unsafe-eval."),
		an("csp-wildcard-script-source", "CSP allows a wildcard script source", "cspWildcardScript",
			CategoryHeaders, SeverityInfo,
			"The effective script-src permits any host via *, http:, https:, or data:. A wildcard inside a specific host such as https://*.cdn.example.com narrows rather than widens the policy and is not reported."),
		// Other response headers.
		an("missing-x-frame-options", "Clickjacking protection missing", "missingFrameOptions",
			CategoryHeaders, SeverityInfo,
			"Neither X-Frame-Options nor a CSP frame-ancestors directive is present. Not reported when frame-ancestors is set, since it supersedes the older header."),
		an("invalid-x-frame-options", "X-Frame-Options value is invalid", "invalidFrameOptions",
			CategoryHeaders, SeverityInfo,
			"The value is ALLOW-FROM or otherwise unrecognized, so no modern browser enforces it."),
		an("missing-x-content-type-options", "X-Content-Type-Options missing", "missingContentTypeOptions",
			CategoryHeaders, SeverityInfo,
			"No nosniff directive on an HTML, JavaScript, JSON, or CSS response. Not evaluated for images, fonts, or downloads."),
		an("x-xss-protection-disabled", "X-XSS-Protection explicitly disabled", "xssProtectionDisabled",
			CategoryHeaders, SeverityInfo,
			"The header is set to 0, explicitly turning off the legacy browser XSS auditor. The header is obsolete, so this only fires on that explicit opt-out and never on its absence — which makes it precise and rare rather than noisy."),

		// CORS.
		an("cors-wildcard-origin", "Access-Control-Allow-Origin is a wildcard", "corsWildcard",
			CategoryHeaders, SeverityMedium,
			"Any origin may read this response. Escalated to medium when the request carried a Cookie or Authorization header, since the endpoint is authenticated."),
		an("cors-reflected-origin-with-credentials", "CORS reflects Origin with credentials", "corsReflectedWithCreds",
			CategoryHeaders, SeverityLow,
			"Access-Control-Allow-Credentials is true and the allowed origin echoes the cross-origin request Origin, so any site can read authenticated responses. Fully detectable from an ordinary browsing session."),
		an("cors-null-origin-allowed", "CORS allows the null origin", "corsNullOrigin",
			CategoryHeaders, SeverityLow,
			"A null origin is reachable from a sandboxed iframe or a data: URL."),
		an("cors-credentials-with-wildcard", "CORS combines credentials with a wildcard", "corsCredsWithWildcard",
			CategoryHeaders, SeverityInfo,
			"Browsers reject this combination outright, so it is a server bug rather than an exposure."),

		// Transport and content mixing.
		perURL(an("insecure-redirect", "Redirect downgrades to HTTP", "insecureRedirect",
			CategoryHeaders, SeverityLow,
			"A redirect sends the client from HTTPS to a plain-HTTP location.")),
		an("insecure-transport-html", "Page served over plain HTTP", "insecureTransportHTML",
			CategoryHeaders, SeverityInfo,
			"An HTML document delivered without TLS."),
		perURL(an("mixed-content-reference", "Mixed content referenced", "mixedContent",
			CategoryHeaders, SeverityInfo,
			"An HTTPS page references a subresource over plain HTTP. XML namespace and schema URLs are excluded, without which this rule fires on every inline SVG.")),
		an("cache-control-authenticated", "Authenticated response is cacheable", "cacheControlAuthenticated",
			CategoryHeaders, SeverityInfo,
			"The request carried credentials and the response lacks no-store, so a shared cache may serve one user's private data to another. Reported as info because a CDN in front of the app often makes this benign."),

		// Cookies.
		an("cookie-missing-secure", "Session cookie missing Secure", "cookieMissingSecure",
			CategoryCookies, SeverityInfo,
			"A session-like cookie set over HTTPS without the Secure attribute."),
		an("cookie-set-over-http", "Session cookie set over plain HTTP", "cookieSetOverHTTP",
			CategoryCookies, SeverityInfo,
			"A session-like cookie issued without TLS, so it crosses the network in cleartext."),
		an("cookie-missing-httponly", "Session cookie missing HttpOnly", "cookieMissingHTTPOnly",
			CategoryCookies, SeverityInfo,
			"A session-like cookie readable from JavaScript. Double-submit CSRF cookies such as XSRF-TOKEN are excluded, because they are required to be script-readable."),
		an("cookie-missing-samesite", "Cookie missing SameSite", "cookieMissingSameSite",
			CategoryCookies, SeverityInfo,
			"No SameSite attribute. Reported as info because browsers now default to Lax."),
		an("cookie-samesite-none-insecure", "SameSite=None without Secure", "cookieSameSiteNoneInsecure",
			CategoryCookies, SeverityInfo,
			"Browsers reject the cookie entirely, so this is both a functional bug and a cross-site exposure wherever it is honoured."),
		an("cookie-overly-broad-domain", "Cookie scoped to a parent domain", "cookieOverbroadDomain",
			CategoryCookies, SeverityInfo,
			"The Domain attribute is two or more labels broader than the response host, exposing the cookie to sibling subdomains."),
		an("cookie-jwt-value", "Cookie contains a JWT", "cookieJWTValue",
			CategoryCookies, SeverityInfo,
			"A cookie value is a JSON Web Token. Evidence records decoded claim names only, never the signature."),

		// Credentials and tokens.
		an("basic-auth-header", "HTTP Basic credentials in request", "basicAuthHeader",
			CategoryCredentials, SeverityHigh,
			"An Authorization: Basic header that base64-decodes to a credential pair. Reported as high over plain HTTP and medium over HTTPS."),
		an("jwt-alg-none", "JWT with alg=none", "jwtAlgNone",
			CategorySecrets, SeverityCritical,
			"A token whose header declares no signature algorithm, so its claims are trivially forgeable."),
		an("jwt-sensitive-claims", "JWT carries sensitive claims", "jwtSensitiveClaims",
			CategorySecrets, SeverityHigh,
			"A token payload contains a password, secret, or government identifier, or has no expiry claim."),

		// Authentication surfaces.
		perURL(an("login-form", "Login form", "loginForm",
			CategoryAccess, SeverityInfo,
			"A password input in an HTML document. Reported as info because a login page is expected; the value is a complete inventory of authentication surfaces.")),
		perURL(an("login-form-over-http", "Login form submits over plain HTTP", "loginFormOverHTTP",
			CategoryAccess, SeverityLow,
			"A password form served over HTTP, or served over HTTPS with an http:// form action. The second variant is the easier one to miss.")),
		perURL(an("login-form-action-cross-origin", "Login form posts to another origin", "loginFormCrossOrigin",
			CategoryAccess, SeverityLow,
			"A password form whose action targets a different host than the page.")),
		perURL(an("password-submitted-over-http", "Password submitted over plain HTTP", "passwordSubmittedOverHTTP",
			CategoryCredentials, SeverityHigh,
			"A request over plain HTTP carrying a password parameter with a value, in a query string, form body, or JSON body.")),

		// Structured credential exposure.
		perURL(an("dotenv-dump", "Environment file contents exposed", "dotenvDump",
			CategoryCredentials, SeverityHigh,
			"A response body shaped like a .env file with at least one sensitive key name. Evidence records key names only, never values.")),
		perURL(an("kubeconfig-or-cloud-credential", "Cloud or cluster credential file exposed", "kubeconfigOrCloudCredential",
			CategoryCredentials, SeverityHigh,
			"A kubeconfig with embedded client key or token, or an AWS shared-credentials file.")),
		perURL(an("pii-bulk-exposure", "Bulk personal data exposure", "piiBulkExposure",
			CategoryPII, SeverityCritical,
			"A single response containing personal data at volume. Fires in place of the individual PII rules so a data dump is one actionable finding rather than hundreds of rows.")),
		an("aws-key-pair", "AWS access key and secret together", "awsKeyPair",
			CategorySecrets, SeverityHigh,
			"An access key ID and a 40-character secret in the same response, which is a complete, immediately usable credential."),
	}
}

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

// isHTTPS reports whether the message was delivered over TLS.
func isHTTPS(m *Message) bool { return strings.EqualFold(m.Scheme, "https") }

// hdr returns a trimmed response header value.
func hdr(m *Message, name string) string {
	if m.RespHeader == nil {
		return ""
	}
	return strings.TrimSpace(m.RespHeader.Get(name))
}

// reqHdr returns a trimmed request header value.
func reqHdr(m *Message, name string) string {
	if m.ReqHeader == nil {
		return ""
	}
	return strings.TrimSpace(m.ReqHeader.Get(name))
}

// requestAuthenticated reports whether the request carried credentials. CORS and
// caching analyzers use it to set severity.
func requestAuthenticated(m *Message) bool {
	return reqHdr(m, "Authorization") != "" || reqHdr(m, "Cookie") != ""
}

// cspDirectives parses a CSP into directive name to token list.
func cspDirectives(policy string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		out[strings.ToLower(fields[0])] = fields[1:]
	}
	return out
}

// effectiveScriptSrc resolves the directive that actually governs scripts,
// following CSP's fallback chain.
func effectiveScriptSrc(d map[string][]string) ([]string, bool) {
	for _, name := range []string{"script-src", "script-src-elem", "default-src"} {
		if v, ok := d[name]; ok {
			return v, true
		}
	}
	return nil, false
}

// hasNonceOrHash reports whether a source list carries a nonce or hash. CSP3
// browsers ignore unsafe-inline when one is present.
func hasNonceOrHash(tokens []string) bool {
	for _, t := range tokens {
		s := strings.ToLower(strings.Trim(t, "'\""))
		if strings.HasPrefix(s, "nonce-") || strings.HasPrefix(s, "sha256-") ||
			strings.HasPrefix(s, "sha384-") || strings.HasPrefix(s, "sha512-") {
			return true
		}
	}
	return false
}

// hasToken reports whether a source list contains an exact token.
func hasToken(tokens []string, want string) bool {
	for _, t := range tokens {
		if strings.EqualFold(strings.Trim(t, "'\""), strings.Trim(want, "'")) {
			return true
		}
	}
	return false
}

// responseCSP returns the enforced policy, or the report-only one if that is all
// there is, plus whether the policy found is enforced.
func responseCSP(m *Message) (policy string, enforced bool) {
	if p := hdr(m, "Content-Security-Policy"); p != "" {
		return p, true
	}
	return hdr(m, "Content-Security-Policy-Report-Only"), false
}

// ---------------------------------------------------------------------------
// Transport security analyzers
// ---------------------------------------------------------------------------

func anMissingHSTS(m *Message, emit func(AnalyzerHit)) {
	// Browsers ignore HSTS on plain HTTP.
	if !isHTTPS(m) || hdr(m, "Strict-Transport-Security") != "" {
		return
	}
	if m.RespStatus < 200 || m.RespStatus >= 400 {
		return
	}
	emit(AnalyzerHit{Evidence: "no Strict-Transport-Security header on an HTTPS response"})
}

func anWeakHSTS(m *Message, emit func(AnalyzerHit)) {
	v := hdr(m, "Strict-Transport-Security")
	if v == "" || !isHTTPS(m) {
		return
	}
	maxAge, ok := hstsMaxAge(v)
	if !ok {
		emit(AnalyzerHit{Evidence: "Strict-Transport-Security has no max-age: " + v})
		return
	}
	const sixMonths = 15552000
	if maxAge < sixMonths {
		emit(AnalyzerHit{Evidence: "max-age=" + strconv.Itoa(maxAge) + " (below 180 days)"})
	}
}

// hstsMaxAge extracts the max-age value from an HSTS header.
func hstsMaxAge(v string) (int, bool) {
	for _, part := range strings.Split(v, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "max-age") {
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(kv[1]), `"`))
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func anInsecureTransportHTML(m *Message, emit func(AnalyzerHit)) {
	if isHTTPS(m) || !m.IsHTMLDocument() {
		return
	}
	emit(AnalyzerHit{Evidence: "HTML document served over plain HTTP"})
}

func anInsecureRedirect(m *Message, emit func(AnalyzerHit)) {
	if m.RespStatus < 300 || m.RespStatus >= 400 || !isHTTPS(m) {
		return
	}
	loc := hdr(m, "Location")
	if strings.HasPrefix(strings.ToLower(loc), "http://") {
		emit(AnalyzerHit{Evidence: "Location: " + loc})
	}
}

// xmlNamespaceHosts are hosts appearing in XML namespace, DOCTYPE, and schema
// URLs. Excluded from the mixed-content check.
var xmlNamespaceHosts = []string{
	"www.w3.org", "w3.org", "schema.org", "schemas.xmlsoap.org", "purl.org",
	"ns.adobe.com", "www.inkscape.org", "sodipodi.sourceforge.net",
	"openoffice.org", "docbook.org", "xml.apache.org", "java.sun.com",
}

var mixedContentRe = regexp.MustCompile(`(?i)\b(?:src|href|action|data-src)\s*=\s*["'](http://[^"']{4,300})["']`)

func anMixedContent(m *Message, emit func(AnalyzerHit)) {
	if !isHTTPS(m) || !m.IsHTMLDocument() {
		return
	}
	seen := map[string]struct{}{}
	for _, match := range mixedContentRe.FindAllStringSubmatch(string(m.RespBody), 40) {
		raw := match[1]
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		skip := false
		for _, host := range xmlNamespaceHosts {
			if strings.EqualFold(u.Host, host) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if _, dup := seen[u.Host]; dup {
			continue
		}
		seen[u.Host] = struct{}{}
		emit(AnalyzerHit{Detail: u.Host, Evidence: raw, GroupExtra: u.Host})
		if len(seen) >= 3 {
			return
		}
	}
}

func anCacheControlAuthenticated(m *Message, emit func(AnalyzerHit)) {
	if m.RespStatus < 200 || m.RespStatus >= 300 || !requestAuthenticated(m) {
		return
	}
	cc := strings.ToLower(hdr(m, "Cache-Control"))
	if strings.Contains(cc, "no-store") {
		return
	}
	kw := contentTypeKeyword(m.ContentType)
	if kw != "html" && kw != "json" {
		return
	}
	if cc == "" {
		emit(AnalyzerHit{Evidence: "authenticated response with no Cache-Control"})
		return
	}
	emit(AnalyzerHit{Evidence: "Cache-Control: " + hdr(m, "Cache-Control")})
}

// ---------------------------------------------------------------------------
// CSP analyzers
// ---------------------------------------------------------------------------

func anMissingCSP(m *Message, emit func(AnalyzerHit)) {
	// Only documents are evaluated; a CSP on a JSON response or an image has no
	// effect.
	if !m.IsHTMLDocument() {
		return
	}
	if hdr(m, "Content-Security-Policy") != "" || hdr(m, "Content-Security-Policy-Report-Only") != "" {
		return
	}
	emit(AnalyzerHit{Evidence: "no Content-Security-Policy on an HTML document"})
}

func anCSPReportOnly(m *Message, emit func(AnalyzerHit)) {
	if !m.IsHTMLDocument() {
		return
	}
	if hdr(m, "Content-Security-Policy") != "" {
		return
	}
	if ro := hdr(m, "Content-Security-Policy-Report-Only"); ro != "" {
		emit(AnalyzerHit{Evidence: "only Content-Security-Policy-Report-Only is set; the policy is not enforced"})
	}
}

func anCSPUnsafeInline(m *Message, emit func(AnalyzerHit)) {
	if !m.IsHTMLDocument() {
		return
	}
	policy, _ := responseCSP(m)
	if policy == "" {
		return
	}
	src, ok := effectiveScriptSrc(cspDirectives(policy))
	if !ok || !hasToken(src, "unsafe-inline") {
		return
	}
	// A nonce or hash makes CSP3 browsers ignore unsafe-inline entirely.
	if hasNonceOrHash(src) {
		return
	}
	emit(AnalyzerHit{Evidence: "script-src allows 'unsafe-inline' with no nonce or hash"})
}

func anCSPUnsafeEval(m *Message, emit func(AnalyzerHit)) {
	if !m.IsHTMLDocument() {
		return
	}
	policy, _ := responseCSP(m)
	if policy == "" {
		return
	}
	if src, ok := effectiveScriptSrc(cspDirectives(policy)); ok && hasToken(src, "unsafe-eval") {
		emit(AnalyzerHit{Evidence: "script-src allows 'unsafe-eval'"})
	}
}

func anCSPWildcardScript(m *Message, emit func(AnalyzerHit)) {
	if !m.IsHTMLDocument() {
		return
	}
	policy, _ := responseCSP(m)
	if policy == "" {
		return
	}
	src, ok := effectiveScriptSrc(cspDirectives(policy))
	if !ok {
		return
	}
	for _, t := range src {
		s := strings.ToLower(strings.Trim(t, "'\""))
		// A bare wildcard or bare scheme permits any host. A wildcard inside a
		// specific host (https://*.cdn.example.com) narrows the policy and is not
		// reported.
		if s == "*" || s == "http:" || s == "https:" || s == "data:" {
			emit(AnalyzerHit{Evidence: "script-src permits any host via " + s})
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Other header analyzers
// ---------------------------------------------------------------------------

func anMissingFrameOptions(m *Message, emit func(AnalyzerHit)) {
	if !m.IsHTMLDocument() {
		return
	}
	if hdr(m, "X-Frame-Options") != "" {
		return
	}
	// frame-ancestors supersedes X-Frame-Options.
	policy, _ := responseCSP(m)
	if policy != "" {
		if _, ok := cspDirectives(policy)["frame-ancestors"]; ok {
			return
		}
	}
	emit(AnalyzerHit{Evidence: "neither X-Frame-Options nor CSP frame-ancestors is present"})
}

func anInvalidFrameOptions(m *Message, emit func(AnalyzerHit)) {
	v := hdr(m, "X-Frame-Options")
	if v == "" || !m.IsHTMLDocument() {
		return
	}
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "DENY", "SAMEORIGIN":
		return
	}
	emit(AnalyzerHit{Evidence: "X-Frame-Options: " + v + " (not enforced by modern browsers)"})
}

func anMissingContentTypeOptions(m *Message, emit func(AnalyzerHit)) {
	if m.RespStatus < 200 || m.RespStatus >= 300 {
		return
	}
	switch contentTypeKeyword(m.ContentType) {
	case "html", "js", "json", "css":
	default:
		// Images, fonts, and downloads are not sniffable in a way that matters.
		return
	}
	if strings.EqualFold(hdr(m, "X-Content-Type-Options"), "nosniff") {
		return
	}
	emit(AnalyzerHit{Evidence: "no X-Content-Type-Options: nosniff"})
}

func anXSSProtectionDisabled(m *Message, emit func(AnalyzerHit)) {
	v := hdr(m, "X-XSS-Protection")
	if strings.HasPrefix(strings.TrimSpace(v), "0") {
		emit(AnalyzerHit{Evidence: "X-XSS-Protection: " + v})
	}
}

// ---------------------------------------------------------------------------
// CORS analyzers
// ---------------------------------------------------------------------------

func anCORSWildcard(m *Message, emit func(AnalyzerHit)) {
	if hdr(m, "Access-Control-Allow-Origin") != "*" {
		return
	}
	// Severity depends on whether the request was authenticated.
	if requestAuthenticated(m) {
		emit(AnalyzerHit{
			Severity: SeverityMedium,
			Evidence: "Access-Control-Allow-Origin: * on a request that carried credentials",
		})
		return
	}
	emit(AnalyzerHit{
		Severity: SeverityInfo,
		Evidence: "Access-Control-Allow-Origin: * on an unauthenticated request",
	})
}

func anCORSReflectedWithCreds(m *Message, emit func(AnalyzerHit)) {
	if !strings.EqualFold(hdr(m, "Access-Control-Allow-Credentials"), "true") {
		return
	}
	acao := hdr(m, "Access-Control-Allow-Origin")
	origin := reqHdr(m, "Origin")
	if acao == "" || origin == "" || !strings.EqualFold(acao, origin) {
		return
	}
	// Reflecting the page's own origin is normal; only a cross-origin reflection
	// with credentials enabled is reported.
	if ou, err := url.Parse(origin); err == nil && ou.Host != "" &&
		strings.EqualFold(ou.Host, m.Host) {
		return
	}
	emit(AnalyzerHit{
		Evidence: "Access-Control-Allow-Origin echoes " + origin + " with Access-Control-Allow-Credentials: true",
	})
}

func anCORSNullOrigin(m *Message, emit func(AnalyzerHit)) {
	if strings.EqualFold(hdr(m, "Access-Control-Allow-Origin"), "null") {
		emit(AnalyzerHit{Evidence: "Access-Control-Allow-Origin: null"})
	}
}

func anCORSCredsWithWildcard(m *Message, emit func(AnalyzerHit)) {
	if hdr(m, "Access-Control-Allow-Origin") == "*" &&
		strings.EqualFold(hdr(m, "Access-Control-Allow-Credentials"), "true") {
		emit(AnalyzerHit{Evidence: "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true (rejected by browsers)"})
	}
}

// ---------------------------------------------------------------------------
// Cookie analyzers
// ---------------------------------------------------------------------------

// cookieAttrs is a parsed Set-Cookie header.
type cookieAttrs struct {
	Name, Value, Domain, SameSite string
	Secure, HTTPOnly              bool
	HasSameSite                   bool
}

// parseSetCookie parses a Set-Cookie value into its name, value, and attributes.
func parseSetCookie(raw string) (cookieAttrs, bool) {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return cookieAttrs{}, false
	}
	nv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nv) != 2 || nv[0] == "" {
		return cookieAttrs{}, false
	}
	c := cookieAttrs{Name: strings.TrimSpace(nv[0]), Value: strings.TrimSpace(nv[1])}
	for _, p := range parts[1:] {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := ""
		if len(kv) == 2 {
			val = strings.TrimSpace(kv[1])
		}
		switch key {
		case "secure":
			c.Secure = true
		case "httponly":
			c.HTTPOnly = true
		case "domain":
			c.Domain = strings.TrimPrefix(strings.ToLower(val), ".")
		case "samesite":
			c.SameSite = val
			c.HasSameSite = true
		}
	}
	return c, true
}

var sessionCookieNameRe = regexp.MustCompile(`(?i)(^|[_.-])(sess(ion)?|sid|token|jwt|auth|authz|login|logon|remember(me)?|persistent|identity|oauth|sso|saml|access|refresh|id_token)([_.-]|$)`)

// knownSessionCookies are exact names used by common frameworks and load
// balancers that the name pattern does not catch.
var knownSessionCookies = map[string]struct{}{
	"phpsessid": {}, "jsessionid": {}, "asp.net_sessionid": {}, "connect.sid": {},
	"laravel_session": {}, "_session_id": {}, "cfid": {}, "cftoken": {},
	"jsessionidsso": {}, "simplesamlsessionid": {}, "awselb": {}, "awsalb": {},
	"awsalbcors": {}, "srvname": {}, "sessionid": {}, "session_id": {},
	"csrf_session": {}, "sails.sid": {}, "express.sid": {},
}

// nonSessionCookies never carry authentication state (analytics, consent) and
// are exempt from the cookie flag checks.
var nonSessionCookies = map[string]struct{}{
	"_ga": {}, "_gid": {}, "_gat": {}, "_gcl_au": {}, "_fbp": {}, "_fbc": {},
	"_hjid": {}, "_clck": {}, "_clsk": {}, "ajs_anonymous_id": {},
	"optanonconsent": {}, "optanonalertboxclosed": {}, "cookieconsent": {},
	"cookie_notice_accepted": {}, "locale": {}, "lang": {}, "language": {},
	"i18n": {}, "tz": {}, "timezone": {}, "theme": {}, "colorscheme": {},
	"currency": {}, "country": {}, "sidebar_state": {}, "next_locale": {},
}

// csrfCookies are double-submit CSRF tokens, which must be readable from
// JavaScript and so are exempt from the HttpOnly check.
var csrfCookies = map[string]struct{}{
	"xsrf-token": {}, "csrftoken": {}, "csrf-token": {}, "_csrf": {},
	"x-csrf-token": {}, "ct0": {}, "csrf": {}, "_csrf_token": {},
}

// isSessionish reports whether a cookie plausibly carries authentication state.
func isSessionish(c cookieAttrs) bool {
	lower := strings.ToLower(c.Name)
	if _, ok := nonSessionCookies[lower]; ok {
		return false
	}
	// Google Analytics property-scoped cookies (_ga_XXXX).
	if strings.HasPrefix(lower, "_ga_") || strings.HasPrefix(lower, "_hj") ||
		strings.HasPrefix(lower, "__utm") || strings.HasPrefix(lower, "intercom-id-") {
		return false
	}
	if _, ok := knownSessionCookies[lower]; ok {
		return true
	}
	if strings.HasPrefix(lower, "bigipserver") || strings.HasPrefix(lower, "aspsessionid") ||
		strings.HasPrefix(lower, "sess") {
		return true
	}
	if sessionCookieNameRe.MatchString(c.Name) {
		return true
	}
	// A long, high-entropy value is session-shaped under any name.
	return len(c.Value) >= 16 && ShannonEntropy(c.Value) >= 3.2
}

// eachSessionCookie runs fn for every session-like cookie in the response.
func eachSessionCookie(m *Message, fn func(cookieAttrs)) {
	for _, raw := range m.SetCookies() {
		c, ok := parseSetCookie(raw)
		if !ok || !isSessionish(c) {
			continue
		}
		fn(c)
	}
}

func anCookieMissingSecure(m *Message, emit func(AnalyzerHit)) {
	// Over plain HTTP, cookie-set-over-http reports this instead.
	if !isHTTPS(m) {
		return
	}
	eachSessionCookie(m, func(c cookieAttrs) {
		if c.Secure {
			return
		}
		emit(AnalyzerHit{
			Detail: c.Name, GroupExtra: c.Name,
			Evidence: c.Name + " set without the Secure attribute",
		})
	})
}

func anCookieSetOverHTTP(m *Message, emit func(AnalyzerHit)) {
	if isHTTPS(m) {
		return
	}
	eachSessionCookie(m, func(c cookieAttrs) {
		emit(AnalyzerHit{
			Detail: c.Name, GroupExtra: c.Name,
			Evidence: c.Name + " issued over plain HTTP",
		})
	})
}

func anCookieMissingHTTPOnly(m *Message, emit func(AnalyzerHit)) {
	eachSessionCookie(m, func(c cookieAttrs) {
		if c.HTTPOnly {
			return
		}
		// Double-submit CSRF cookies must be script-readable.
		if _, isCSRF := csrfCookies[strings.ToLower(c.Name)]; isCSRF {
			return
		}
		emit(AnalyzerHit{
			Detail: c.Name, GroupExtra: c.Name,
			Evidence: c.Name + " is readable from JavaScript (no HttpOnly)",
		})
	})
}

func anCookieMissingSameSite(m *Message, emit func(AnalyzerHit)) {
	eachSessionCookie(m, func(c cookieAttrs) {
		if c.HasSameSite {
			return
		}
		emit(AnalyzerHit{
			Detail: c.Name, GroupExtra: c.Name,
			Evidence: c.Name + " has no SameSite attribute (browser default is Lax)",
		})
	})
}

func anCookieSameSiteNoneInsecure(m *Message, emit func(AnalyzerHit)) {
	for _, raw := range m.SetCookies() {
		c, ok := parseSetCookie(raw)
		if !ok || !strings.EqualFold(c.SameSite, "None") || c.Secure {
			continue
		}
		emit(AnalyzerHit{
			Detail: c.Name, GroupExtra: c.Name,
			Evidence: c.Name + " uses SameSite=None without Secure, so browsers reject it entirely",
		})
	}
}

func anCookieOverbroadDomain(m *Message, emit func(AnalyzerHit)) {
	host := strings.ToLower(m.Host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	eachSessionCookie(m, func(c cookieAttrs) {
		if c.Domain == "" || c.Domain == host {
			return
		}
		if !strings.HasSuffix(host, "."+c.Domain) {
			return
		}
		// Two or more extra labels between the host and the cookie domain means the
		// cookie is visible to unrelated sibling subdomains.
		extra := strings.Count(strings.TrimSuffix(host, "."+c.Domain), ".") + 1
		if extra < 2 {
			return
		}
		emit(AnalyzerHit{
			Detail: c.Name, GroupExtra: c.Name,
			Evidence: c.Name + " scoped to ." + c.Domain + " from " + host,
		})
	})
}

var jwtValueRe = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$`)

func anCookieJWTValue(m *Message, emit func(AnalyzerHit)) {
	for _, raw := range m.SetCookies() {
		c, ok := parseSetCookie(raw)
		if !ok || !jwtValueRe.MatchString(c.Value) {
			continue
		}
		claims, _ := decodeJWTSegment(c.Value, 1)
		detail := c.Name
		evidence := c.Name + " contains a JWT"
		if len(claims) > 0 {
			evidence += " with claims: " + strings.Join(claimNames(claims), ", ")
		}
		emit(AnalyzerHit{Detail: detail, GroupExtra: c.Name, Evidence: evidence})
	}
}

// ---------------------------------------------------------------------------
// Credential and token analyzers
// ---------------------------------------------------------------------------

// The trailing class includes \r: raw header blocks are CRLF-framed and Go's
// multiline `$` matches before the \n, leaving the \r unconsumed.
var basicAuthRe = regexp.MustCompile(`(?im)^authorization:[ \t]*basic[ \t]+([A-Za-z0-9+/=]{8,})[ \t\r]*$`)

func anBasicAuthHeader(m *Message, emit func(AnalyzerHit)) {
	match := basicAuthRe.FindSubmatchIndex(m.ReqRawHdr)
	if match == nil {
		return
	}
	payload := string(m.ReqRawHdr[match[2]:match[3]])
	dec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return
	}
	creds := string(dec)
	idx := strings.IndexByte(creds, ':')
	if idx < 0 {
		return
	}
	for _, r := range creds {
		if r > 127 || (r < 0x20 && r != '\t') {
			return
		}
	}
	user := creds[:idx]
	// Severity does not vary by transport; the transport is recorded in the
	// evidence.
	note := "over HTTPS"
	if !isHTTPS(m) {
		note = "over plain HTTP, recoverable from the network"
	}
	emit(AnalyzerHit{
		Detail:   user,
		Evidence: "Authorization: Basic " + user + ":*** (" + note + ")",
		// The highlight covers the base64 payload, not the whole header.
		Offset: match[2], OffsetIn: TargetRequestHeader, OffsetLen: match[3] - match[2],
	})
}

// decodeJWTSegment base64url-decodes one segment of a JWT into a claim map.
func decodeJWTSegment(token string, index int) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if index >= len(parts) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil, false
	}
	return out, true
}

// claimNames returns sorted-ish claim keys for evidence, capped for brevity.
func claimNames(claims map[string]any) []string {
	out := make([]string, 0, len(claims))
	for k := range claims {
		out = append(out, k)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// jwtsInMessage collects JWT-shaped tokens from the request headers and the
// response body once, shared by the token analyzers.
func jwtsInMessage(m *Message) []string {
	re := regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)`)
	var out []string
	seen := map[string]struct{}{}
	add := func(buf []byte) {
		for _, mm := range re.FindAllSubmatch(buf, 10) {
			t := string(mm[1])
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	add(m.ReqRawHdr)
	if m.BodyScannable {
		add(m.RespBody)
	}
	add(m.RespRawHdr)
	return out
}

func anJWTAlgNone(m *Message, emit func(AnalyzerHit)) {
	for _, tok := range jwtsInMessage(m) {
		hdrClaims, ok := decodeJWTSegment(tok, 0)
		if !ok {
			continue
		}
		alg, _ := hdrClaims["alg"].(string)
		if strings.EqualFold(alg, "none") {
			emit(AnalyzerHit{
				Detail:   "alg=none",
				Evidence: "JWT header declares alg=none, so the signature is not verified",
			})
			return
		}
	}
}

// sensitiveClaimRe matches claim names that should never appear in a token.
var sensitiveClaimRe = regexp.MustCompile(`(?i)^(password|passwd|pwd|secret|ssn|social_?security|credit_?card|card_?number|api_?key|private_?key)$`)

func anJWTSensitiveClaims(m *Message, emit func(AnalyzerHit)) {
	for _, tok := range jwtsInMessage(m) {
		claims, ok := decodeJWTSegment(tok, 1)
		if !ok {
			continue
		}
		for name := range claims {
			if sensitiveClaimRe.MatchString(name) {
				emit(AnalyzerHit{
					Detail:     name,
					GroupExtra: name,
					Evidence:   "JWT payload contains the claim " + name,
				})
				return
			}
		}
		if _, hasExp := claims["exp"]; !hasExp && len(claims) > 0 {
			emit(AnalyzerHit{
				Detail:     "no exp",
				GroupExtra: "no-exp",
				Evidence:   "JWT payload has no exp claim, so the token never expires",
			})
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Authentication surface analyzers
// ---------------------------------------------------------------------------

var (
	passwordInputRe = regexp.MustCompile(`(?i)<input[^>]{0,400}?\btype\s*=\s*["']?password\b`)
	formActionRe    = regexp.MustCompile(`(?i)<form[^>]{0,400}?\baction\s*=\s*["']([^"']{0,300})["']`)
	titleRe         = regexp.MustCompile(`(?i)<title[^>]*>([^<]{0,120})</title>`)
)

// hasPasswordInput is the login-page detection primitive: a password input in an
// HTML document.
func hasPasswordInput(m *Message) bool {
	return m.IsHTMLDocument() && passwordInputRe.Match(m.RespBody)
}

// pageTitle returns the document title, for evidence.
func pageTitle(m *Message) string {
	if mm := titleRe.FindSubmatch(m.RespBody); mm != nil {
		return strings.TrimSpace(string(mm[1]))
	}
	return ""
}

// formActions returns the action attributes of forms in the document.
func formActions(m *Message) []string {
	var out []string
	for _, mm := range formActionRe.FindAllSubmatch(m.RespBody, 10) {
		out = append(out, string(mm[1]))
	}
	return out
}

func anLoginForm(m *Message, emit func(AnalyzerHit)) {
	if !hasPasswordInput(m) {
		return
	}
	ev := "password input present"
	if t := pageTitle(m); t != "" {
		ev += " (title: " + t + ")"
	}
	emit(AnalyzerHit{Evidence: ev})
}

func anLoginFormOverHTTP(m *Message, emit func(AnalyzerHit)) {
	if !hasPasswordInput(m) {
		return
	}
	if !isHTTPS(m) {
		emit(AnalyzerHit{Evidence: "password form served over plain HTTP"})
		return
	}
	// HTTPS page, http:// form action: the credentials still cross the network in
	// cleartext.
	for _, action := range formActions(m) {
		if strings.HasPrefix(strings.ToLower(action), "http://") {
			emit(AnalyzerHit{Evidence: "HTTPS page posts credentials to " + action})
			return
		}
	}
}

func anLoginFormCrossOrigin(m *Message, emit func(AnalyzerHit)) {
	if !hasPasswordInput(m) {
		return
	}
	host := m.Host
	for _, action := range formActions(m) {
		u, err := url.Parse(action)
		if err != nil || u.Host == "" || strings.EqualFold(u.Host, host) {
			continue
		}
		emit(AnalyzerHit{Detail: u.Host, Evidence: "password form action targets " + u.Host})
		return
	}
}

var passwordParamRe = regexp.MustCompile(`(?i)(^|[&"'{,\s])(password|passwd|pwd|pass|passphrase|otp|pin)("?\s*[:=]|=)`)

func anPasswordSubmittedOverHTTP(m *Message, emit func(AnalyzerHit)) {
	if isHTTPS(m) || m.Req == nil {
		return
	}
	// Query string.
	if m.URL != nil && m.URL.RawQuery != "" {
		q := m.URL.Query()
		for k, vals := range q {
			if passwordParamRe.MatchString(k+"=") && len(vals) > 0 && vals[0] != "" {
				emit(AnalyzerHit{
					Detail:   k,
					Evidence: m.Req.Method + " " + m.Req.URL + " sends " + k + " in the query string over plain HTTP",
					OffsetIn: TargetURL,
				})
				return
			}
		}
	}
	// Request body. urlencoded, multipart, and JSON all place the parameter name
	// adjacent to a separator, so one pattern covers all three.
	if len(m.ReqBody) > 0 {
		if loc := passwordParamRe.FindIndex(m.ReqBody); loc != nil {
			emit(AnalyzerHit{
				Evidence: m.Req.Method + " " + m.Req.URL + " sends a password parameter in the body over plain HTTP",
				Offset:   loc[0], OffsetIn: TargetRequestBody, OffsetLen: loc[1] - loc[0],
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Structured credential exposure analyzers
// ---------------------------------------------------------------------------

var (
	// In multiline mode `.` excludes newlines, so the value is bounded by the
	// line. RE2 caps explicit repeat counts at 1000, so `.*` is used instead.
	envLineRe      = regexp.MustCompile(`(?m)^([A-Z][A-Z0-9_]{2,48})=.*$`)
	sensitiveEnvRe = regexp.MustCompile(`(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|DSN|DATABASE_URL|CREDENTIAL|SALT|CIPHER|ACCESS_KEY)`)
)

func anDotenvDump(m *Message, emit func(AnalyzerHit)) {
	if !m.BodyScannable {
		return
	}
	// An HTML body is a single-page app's index page returned for an unknown
	// path, not an env file.
	if contentTypeKeyword(m.ContentType) == "html" && !strings.Contains(strings.ToLower(m.Path), ".env") {
		return
	}
	matches := envLineRe.FindAllSubmatch(m.RespBody, 200)
	if len(matches) < 3 {
		return
	}
	var names []string
	sensitive := false
	for _, mm := range matches {
		name := string(mm[1])
		if sensitiveEnvRe.MatchString(name) {
			sensitive = true
			if len(names) < 8 {
				names = append(names, name)
			}
		}
	}
	if !sensitive {
		return
	}
	emit(AnalyzerHit{
		Evidence: strconv.Itoa(len(matches)) + " environment assignments including: " + strings.Join(names, ", "),
	})
}

func anKubeconfigOrCloudCredential(m *Message, emit func(AnalyzerHit)) {
	if !m.BodyScannable {
		return
	}
	body := string(m.RespBody)
	switch {
	case strings.Contains(body, "apiVersion: v1") && strings.Contains(body, "clusters:") &&
		(strings.Contains(body, "client-key-data:") || strings.Contains(body, "token:")):
		emit(AnalyzerHit{Evidence: "kubeconfig with embedded cluster credentials"})
	case strings.Contains(body, "aws_access_key_id") && strings.Contains(body, "aws_secret_access_key"):
		emit(AnalyzerHit{Evidence: "AWS shared credentials file"})
	}
}

var (
	bulkEmailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b`)
	bulkPANRe   = regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{0,4}\b`)
	bulkSSNRe   = regexp.MustCompile(`\b[0-8]\d{2}-\d{2}-\d{4}\b`)
)

// anPIIBulkExposure reports a data dump as one finding, keyed on the volume of
// PII in a single response rather than on any individual value.
func anPIIBulkExposure(m *Message, emit func(AnalyzerHit)) {
	if !m.BodyScannable {
		return
	}
	switch contentTypeKeyword(m.ContentType) {
	case "json", "xml", "csv", "plain":
	default:
		return
	}

	emails := map[string]struct{}{}
	for _, e := range bulkEmailRe.FindAll(m.RespBody, 500) {
		emails[strings.ToLower(string(e))] = struct{}{}
	}
	validPANs := 0
	for _, c := range bulkPANRe.FindAll(m.RespBody, 200) {
		if filterLuhn(filterContext{Match: string(c)}) {
			validPANs++
		}
	}
	validSSNs := 0
	for _, s := range bulkSSNRe.FindAll(m.RespBody, 200) {
		if filterSSN(filterContext{Match: string(s)}) {
			validSSNs++
		}
	}

	var parts []string
	if len(emails) >= 20 {
		parts = append(parts, strconv.Itoa(len(emails))+" email addresses")
	}
	if validPANs >= 5 {
		parts = append(parts, strconv.Itoa(validPANs)+" card numbers")
	}
	if validSSNs >= 5 {
		parts = append(parts, strconv.Itoa(validSSNs)+" SSNs")
	}
	if len(parts) == 0 {
		return
	}
	emit(AnalyzerHit{Evidence: "single response contains " + strings.Join(parts, ", ")})
}

var (
	awsKeyIDRe  = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	awsSecretRe = regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`)
)

// anAWSKeyPair escalates when both halves of an AWS credential appear together.
func anAWSKeyPair(m *Message, emit func(AnalyzerHit)) {
	if !m.BodyScannable {
		return
	}
	id := awsKeyIDRe.Find(m.RespBody)
	if id == nil {
		return
	}
	for _, cand := range awsSecretRe.FindAll(m.RespBody, 50) {
		s := string(cand)
		// Reject template values, content hashes, and low-entropy matches; a
		// 40-character base64 run is a common shape in minified assets.
		if isPlaceholder(s) || !filterNotHashLike(filterContext{Match: s}) {
			continue
		}
		if ShannonEntropy(s) < 4.0 {
			continue
		}
		emit(AnalyzerHit{
			Detail:   string(id),
			Evidence: "access key " + string(id) + " with a 40-character secret in the same response",
		})
		return
	}
}
