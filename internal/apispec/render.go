package apispec

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Target is where rendered bytes are meant to go. It is returned alongside them
// because the senders take scheme and host separately from the request.
type Target struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"` // host[:port]
	Path   string `json:"path"` // origin-form request target, query included
}

// Credential is one concrete secret. It is never part of a parsed Spec: a
// document declares that a scheme exists, never what satisfies it.
type Credential struct {
	// Scheme names the AuthScheme this satisfies. Empty applies it
	// unconditionally, which is what a hand-written header profile wants.
	Scheme string `json:"scheme,omitempty"`

	Kind AuthKind `json:"kind"`

	// In and Name are used for AuthAPIKey, and are normally copied from the
	// scheme the document declared.
	In   ParamIn `json:"in,omitempty"`
	Name string  `json:"name,omitempty"`

	Value    string `json:"value,omitempty"` // bearer token or api key
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Header is a literal header a profile adds.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie is a literal cookie a profile adds.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Auth is everything one profile contributes to a request.
type Auth struct {
	Credentials []Credential `json:"credentials,omitempty"`
	Headers     []Header     `json:"headers,omitempty"`
	Cookies     []Cookie     `json:"cookies,omitempty"`
}

// RenderOptions tunes one render.
type RenderOptions struct {
	// UserAgent is one rung of the ladder Render resolves, most specific first:
	// an auth profile, a value the operator typed for a declared "in: header"
	// parameter, this, the document's generated placeholder, DefaultUserAgent.
	// The request carries exactly one whatever happens.
	UserAgent string

	// Accept defaults to a permissive value when empty.
	Accept string

	// FuzzParam names a parameter to wrap in FuzzMarker, for handing the result
	// to the fuzzer. The marker is placed after encoding, which is why this is
	// done here rather than by searching the rendered bytes: the value may be
	// percent-encoded, may appear more than once, and may live inside a JSON
	// body.
	FuzzParam  string
	FuzzMarker string

	// Omit drops a parameter from the request entirely, keyed by ValueKey. It is
	// distinct from an empty value in Values: absent means "use what the parser
	// generated" and empty means "send it empty", so without this there is no way
	// to express leaving a parameter out — which is exactly the test an operator
	// wants against one the document marks required.
	Omit map[string]bool
}

const defaultAccept = "application/json, text/plain, */*"

// DefaultUserAgent is what a request carries when the operator has named no
// other.
//
// Sending no User-Agent at all is not the quiet option it looks like. These
// bytes reach the target through Joro's own proxy, which parses them and
// forwards with net/http — and net/http substitutes its own Go-http-client
// default for a request that has no User-Agent key. An absent header therefore
// advertises a Go program to the target while showing the operator nothing,
// which is the one combination worth ruling out: a rendered request is only
// trustworthy if it is what leaves the machine.
//
// So a named User-Agent that writeHeader would drop, or that net/http would
// strip as blank, does not count as named — see usableUA.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"

// UserAgentOr returns ua when it is usable as a header value and
// DefaultUserAgent otherwise.
//
// Exported for the raw-request builders outside this package, which concatenate
// their header lines by hand and so do not get writeHeader's CR/LF check.
// Routing an operator-supplied value through here is what keeps a newline in one
// from splitting the header block.
func UserAgentOr(ua string) string {
	if v := usableUA(ua); v != "" {
		return v
	}
	return DefaultUserAgent
}

// isUserAgent reports whether name is the User-Agent header, however spelled.
// A document chooses that spelling, not Joro, so this is case- and
// space-insensitive.
func isUserAgent(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "User-Agent")
}

// usableUA returns value when it will survive both writeHeader and net/http's
// own serialization, and "" otherwise.
//
// Blank and invalid are as good as unnamed: treating either as named suppresses
// DefaultUserAgent, and the request then reaches the target carrying no
// User-Agent at all or net/http's own.
func usableUA(value string) string {
	if strings.TrimSpace(value) == "" || !validHeaderValue(value) {
		return ""
	}
	return value
}

// firstUsableUA picks the first candidate that will reach the wire intact,
// which is how the rungs of the ladder fall through to one another, and
// DefaultUserAgent is the floor none of them can drop past.
func firstUsableUA(candidates ...string) string {
	for _, c := range candidates {
		if v := usableUA(c); v != "" {
			return v
		}
	}
	return DefaultUserAgent
}

// authUserAgent returns the usable User-Agent a profile names, or "". The two
// loops are in applyAuth's order, so last-wins agrees with dedupeHeaders.
func authUserAgent(auth Auth) string {
	ua := ""
	for _, c := range auth.Credentials {
		if c.Kind != AuthAPIKey || c.In == InQuery || c.In == InCookie {
			continue
		}
		if c.Name != "" && c.Value != "" && isUserAgent(c.Name) && validHeaderName(c.Name) {
			ua = usableUA(c.Value)
		}
	}
	for _, h := range auth.Headers {
		if isUserAgent(h.Name) && validHeaderName(h.Name) {
			ua = usableUA(h.Value)
		}
	}
	return ua
}

// Render builds the raw HTTP/1.1 bytes for one operation.
//
// These bytes are the executable truth. The Spec is the editing document, and
// every path from the spec tab to the wire goes through here — there is no
// second rendering anywhere, which is what lets the operator trust that what
// they are shown is what is sent. Nothing in this package transmits them.
func Render(op *Operation, srv Server, vals Values, auth Auth, opts RenderOptions) ([]byte, Target, error) {
	if op == nil {
		return nil, Target{}, fmt.Errorf("no operation")
	}
	scheme, host, err := validateTarget(srv)
	if err != nil {
		return nil, Target{}, err
	}
	if vals == nil {
		vals = Values{}
	}

	marker := opts.FuzzMarker
	if opts.FuzzParam != "" && marker == "" {
		marker = "§"
	}
	mark := func(key, v string) string {
		if opts.FuzzParam != "" && key == opts.FuzzParam {
			return marker + v + marker
		}
		return v
	}

	// Path parameters.
	path := srv.BasePath + op.Path
	queryPairs := make([]string, 0, len(op.Params))
	headers := make([]Header, 0, len(op.Params)+8)
	cookies := make([]Cookie, 0, 4)

	// The two document-side rungs of the User-Agent ladder, filled below: what
	// the operator typed for a declared parameter, and the placeholder the
	// parser generated for one.
	var typedUA, docUA string

	// Exploded object properties are regrouped so the style can be honored: the
	// three forms below are three different requests, and which one the server
	// accepts is not negotiable.
	groups := groupExploded(op.Params)

	for _, prm := range op.Params {
		key := ValueKey(prm.In, prm.Name)
		omitted := opts.Omit[key]
		if omitted && prm.In != InPath {
			// Omitted entirely rather than sent empty. Leaving out a parameter the
			// document marks required is a real test, so it has to be expressible.
			continue
		}
		raw, overridden := vals[key]
		if !overridden {
			raw = prm.Default
		}

		switch prm.In {
		case InPath:
			// A path parameter is part of the template, so it cannot be absent the
			// way a query parameter can — dropping the substitution would only
			// leave "{petId}" for the leftover-brace pass to fill back in, and
			// unticking it would appear to do nothing. Collapsing it to an empty
			// segment is the test that is actually available here, and the one
			// worth having: "/pet/" rather than "/pet/1".
			if omitted {
				raw = ""
			}
			// PathEscape per segment: a value containing "/" becomes %2F, which is
			// what a single path parameter means.
			path = strings.Replace(path, "{"+prm.Name+"}", mark(key, url.PathEscape(raw)), 1)
		case InQuery:
			if prm.ExplodedFrom != "" {
				// Emitted once for the whole group, at the position of its first
				// member, so document order survives.
				if g, ok := groups[prm.ExplodedFrom]; ok && !g.emitted {
					g.emitted = true
					queryPairs = append(queryPairs, renderGroup(g, vals, opts, mark)...)
				}
				continue
			}
			queryPairs = append(queryPairs, renderScalarQuery(prm, raw, key, mark)...)
		case InHeader:
			value := mark(key, raw)
			if isUserAgent(prm.Name) && validHeaderName(prm.Name) {
				if overridden {
					typedUA = usableUA(value)
				} else {
					docUA = usableUA(value)
				}
			}
			headers = append(headers, Header{Name: prm.Name, Value: value})
		case InCookie:
			cookies = append(cookies, Cookie{Name: prm.Name, Value: mark(key, raw)})
		}
	}

	// Any brace left over is a parameter the document never declared. Filling it
	// keeps a literal "{" off the wire; sj leaves them, and the 404s that come
	// back read as "this endpoint does not exist", which is the worst thing a
	// scanner can be wrong about.
	path = fillUndeclaredPathParams(path)

	// Auth is applied after spec parameters so a profile wins over a generated
	// placeholder for the same name.
	headers, queryPairs, cookies = applyAuth(auth, headers, queryPairs, cookies)

	// Resolved here rather than at the write site so there is one answer, and
	// one place to read the precedence off.
	userAgent := firstUsableUA(authUserAgent(auth), typedUA, opts.UserAgent, docUA)

	target := path
	if len(queryPairs) > 0 {
		target += "?" + strings.Join(queryPairs, "&")
	}

	body, contentType := selectBody(op, vals)
	if opts.FuzzParam == ValueKeyBody && len(body) > 0 {
		body = []byte(marker + string(body) + marker)
	}

	// The same guard the host and every header already have. Both halves are
	// document-controlled, and url.Parse percent-decodes BasePath — so a %0d%0a
	// in a served spec would append a second request to every render.
	if err := validateRequestTarget(op.Method, target); err != nil {
		return nil, Target{}, err
	}

	var buf bytes.Buffer
	buf.WriteString(op.Method + " " + target + " HTTP/1.1\r\n")

	writeHeader(&buf, "Host", host)
	writeHeader(&buf, "User-Agent", userAgent)
	accept := opts.Accept
	if accept == "" {
		accept = defaultAccept
	}
	writeHeader(&buf, "Accept", accept)

	for _, h := range headers {
		// User-Agent is skipped because it was resolved and written above; a
		// second line here is what the ladder exists to prevent.
		if reservedHeader(h.Name) || isUserAgent(h.Name) {
			continue
		}
		writeHeader(&buf, h.Name, h.Value)
	}
	if c := buildCookieHeader(cookies); c != "" {
		writeHeader(&buf, "Cookie", c)
	}
	if contentType != "" {
		writeHeader(&buf, "Content-Type", contentType)
	}
	if len(body) > 0 || methodExpectsBody(op.Method) {
		// Computed here from the bytes in hand. proxy.UpdateContentLength exists
		// to repair edited bytes; nothing needs repairing when the body was just
		// built. No Transfer-Encoding, ever.
		writeHeader(&buf, "Content-Length", strconv.Itoa(len(body)))
	}

	buf.WriteString("\r\n")
	buf.Write(body)

	return buf.Bytes(), Target{Scheme: scheme, Host: host, Path: target}, nil
}

// Serialization styles, from OpenAPI 3's `style` keyword.
const (
	StyleForm           = "form"
	StyleSimple         = "simple"
	StyleDeepObject     = "deepObject"
	StyleSpaceDelimited = "spaceDelimited"
	StylePipeDelimited  = "pipeDelimited"
)

// defaultStyleFor returns the style a parameter has when the document does not
// say. It is not the same everywhere: query and cookie default to form, path and
// header to simple.
func defaultStyleFor(in ParamIn) string {
	switch in {
	case InQuery, InCookie:
		return StyleForm
	default:
		return StyleSimple
	}
}

// explodedGroup is one object-schema query parameter, put back together from the
// per-property Params the parser split it into.
type explodedGroup struct {
	parent  string
	style   string
	explode bool
	members []Param
	emitted bool
}

// groupExploded collects the per-property Params belonging to each object
// parameter, preserving document order within the group.
func groupExploded(params []Param) map[string]*explodedGroup {
	groups := map[string]*explodedGroup{}
	for _, prm := range params {
		if prm.In != InQuery || prm.ExplodedFrom == "" {
			continue
		}
		g, ok := groups[prm.ExplodedFrom]
		if !ok {
			g = &explodedGroup{parent: prm.ExplodedFrom, style: prm.Style, explode: prm.Explode}
			groups[prm.ExplodedFrom] = g
		}
		g.members = append(g.members, prm)
	}
	return groups
}

// renderGroup serializes one object parameter according to its style.
//
// The default when a document says nothing is form+explode, which is also what
// every property being its own top-level pair means — so the common case is
// unchanged. The other two are what a document is asking for when it bothers to
// say so, and sending the default instead produces a request the server reads as
// something else entirely: Stripe alone declares deepObject on over a thousand
// parameters.
func renderGroup(g *explodedGroup, vals Values, opts RenderOptions, mark func(string, string) string) []string {
	type kv struct{ name, value, key string }
	present := make([]kv, 0, len(g.members))
	for _, m := range g.members {
		key := ValueKey(m.In, m.Name)
		if opts.Omit[key] {
			continue
		}
		v, ok := vals[key]
		if !ok {
			v = m.Default
		}
		present = append(present, kv{m.Name, v, key})
	}
	if len(present) == 0 {
		return nil
	}

	switch g.style {
	case StyleDeepObject:
		// ?parent[child]=value
		out := make([]string, 0, len(present))
		for _, p := range present {
			name := url.QueryEscape(g.parent) + "%5B" + url.QueryEscape(p.name) + "%5D"
			out = append(out, name+"="+mark(p.key, url.QueryEscape(p.value)))
		}
		return out

	case StyleForm, "":
		if g.explode || g.style == "" {
			// ?child=value, one pair per property — the default.
			out := make([]string, 0, len(present))
			for _, p := range present {
				out = append(out, url.QueryEscape(p.name)+"="+mark(p.key, url.QueryEscape(p.value)))
			}
			return out
		}
		// ?parent=k1,v1,k2,v2
		parts := make([]string, 0, len(present)*2)
		for _, p := range present {
			parts = append(parts, p.name, p.value)
		}
		return []string{url.QueryEscape(g.parent) + "=" + url.QueryEscape(strings.Join(parts, ","))}
	}

	// An unrecognized style falls back to the default shape rather than dropping
	// the parameter; the parser has already recorded a diagnostic for it.
	out := make([]string, 0, len(present))
	for _, p := range present {
		out = append(out, url.QueryEscape(p.name)+"="+mark(p.key, url.QueryEscape(p.value)))
	}
	return out
}

// renderScalarQuery serializes one non-object query parameter.
//
// The value is a single string the operator can see and edit, so a multi-valued
// parameter is expressed by commas in that string and the style decides what
// commas mean on the wire.
func renderScalarQuery(prm Param, raw, key string, mark func(string, string) string) []string {
	name := url.QueryEscape(prm.Name)

	if prm.Type == "array" && raw != "" {
		items := strings.Split(raw, ",")
		if len(items) > 1 {
			switch prm.Style {
			case StyleSpaceDelimited:
				return []string{name + "=" + mark(key, url.QueryEscape(strings.Join(items, " ")))}
			case StylePipeDelimited:
				return []string{name + "=" + mark(key, url.QueryEscape(strings.Join(items, "|")))}
			case StyleForm, "":
				if prm.Explode || prm.Style == "" {
					// Repeat the key, which is what form+explode means for an array
					// and what Swagger 2's collectionFormat: multi meant before it.
					out := make([]string, 0, len(items))
					for _, item := range items {
						out = append(out, name+"="+mark(key, url.QueryEscape(item)))
					}
					return out
				}
			}
		}
	}
	return []string{name + "=" + mark(key, url.QueryEscape(raw))}
}

// validateTarget refuses a server a document should not be able to choose.
func validateTarget(srv Server) (scheme, host string, err error) {
	scheme = strings.ToLower(strings.TrimSpace(srv.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("server scheme %q is not http or https", srv.Scheme)
	}
	host = strings.TrimSpace(srv.Host)
	if host == "" {
		return "", "", fmt.Errorf("no target host: the document declares no server and none was supplied")
	}
	if err := ValidateHost(host); err != nil {
		return "", "", err
	}
	return scheme, host, nil
}

// ValidateHost applies the rules a host must satisfy before it is concatenated
// into a request line or a Host header.
//
// Exported for the raw-request builders outside this package, which otherwise
// get no check. A "user:pass@host" in a server URL is how a document aims a scan
// at a host the operator never read.
func ValidateHost(host string) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("no target host")
	}
	if strings.ContainsAny(host, "@/\\?#") {
		return fmt.Errorf("host %q contains a character that cannot appear in a host", host)
	}
	if strings.ContainsAny(host, " \t\r\n\x00") {
		return fmt.Errorf("host contains whitespace or a control character")
	}
	return nil
}

// validateRequestTarget refuses a method or target that would not stay on one
// request line: RFC 7230 allows only visible ASCII there. Rejecting rather than
// escaping, for validateTarget's reason — a document that produced this was not
// describing an endpoint.
func validateRequestTarget(method, target string) error {
	if method == "" || !validHeaderName(method) {
		return fmt.Errorf("operation method %q is not a token", method)
	}
	if target == "" {
		return fmt.Errorf("operation has an empty request target")
	}
	for i := 0; i < len(target); i++ {
		if target[i] <= 0x20 || target[i] >= 0x7f {
			return fmt.Errorf("request target contains a character that cannot appear on a request line (byte %d at offset %d)", target[i], i)
		}
	}
	return nil
}

// undeclaredPathParam finds "{name}" spans left after substitution.
func fillUndeclaredPathParams(path string) string {
	for {
		open := strings.IndexByte(path, '{')
		if open < 0 {
			return path
		}
		end := strings.IndexByte(path[open:], '}')
		if end < 0 {
			// An unbalanced brace is not a template; leave it rather than eating
			// the rest of the path.
			return path
		}
		path = path[:open] + "1" + path[open+end+1:]
	}
}

// applyAuth places each credential where its scheme says it goes.
//
// All four kinds are applied. sj prompts for an apiKey in a query string and
// then only prints it — it never reaches a request — and it warns about bearer
// rather than accepting one unless the scheme's key happens to be spelled
// "bearer".
func applyAuth(auth Auth, headers []Header, queryPairs []string, cookies []Cookie) ([]Header, []string, []Cookie) {
	for _, c := range auth.Credentials {
		switch c.Kind {
		case AuthBasic:
			if c.Username == "" && c.Password == "" {
				continue
			}
			headers = append(headers, Header{
				Name:  "Authorization",
				Value: "Basic " + basicValue(c.Username, c.Password),
			})
		case AuthBearer:
			if c.Value == "" {
				continue
			}
			headers = append(headers, Header{Name: "Authorization", Value: "Bearer " + c.Value})
		case AuthAPIKey:
			if c.Name == "" || c.Value == "" {
				continue
			}
			switch c.In {
			case InQuery:
				queryPairs = append(queryPairs, url.QueryEscape(c.Name)+"="+url.QueryEscape(c.Value))
			case InCookie:
				cookies = append(cookies, Cookie{Name: c.Name, Value: c.Value})
			default:
				headers = append(headers, Header{Name: c.Name, Value: c.Value})
			}
		}
	}
	headers = append(headers, auth.Headers...)
	cookies = append(cookies, auth.Cookies...)
	return dedupeHeaders(headers), queryPairs, dedupeCookies(cookies)
}

// dedupeHeaders keeps the last value for each name, case-insensitively.
//
// What makes "a profile wins over a generated placeholder" true: appending alone
// emits a second header line, so a document declaring Authorization as a
// parameter sends the placeholder beside the real token — and the resulting 401
// reads as the credentialed profile having no access. Last wins because
// applyAuth appends credentials after the spec's parameters.
func dedupeHeaders(in []Header) []Header {
	last := make(map[string]int, len(in))
	for i, h := range in {
		last[strings.ToLower(h.Name)] = i
	}
	out := make([]Header, 0, len(in))
	for i, h := range in {
		if last[strings.ToLower(h.Name)] == i {
			out = append(out, h)
		}
	}
	return out
}

// dedupeCookies keeps the last value per cookie name, which unlike a header
// name is case-sensitive.
func dedupeCookies(in []Cookie) []Cookie {
	last := make(map[string]int, len(in))
	for i, c := range in {
		last[c.Name] = i
	}
	out := make([]Cookie, 0, len(in))
	for i, c := range in {
		if last[c.Name] == i {
			out = append(out, c)
		}
	}
	return out
}

// reservedHeader names the headers this renderer frames itself. Honoring a
// document's own Host or Content-Length would emit a second copy beside the
// computed one — a smuggling primitive aimed at the operator's proxy.
func reservedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection":
		return true
	}
	return false
}

func basicValue(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// selectBody picks the body bytes and content type for this render.
func selectBody(op *Operation, vals Values) ([]byte, string) {
	if len(op.Bodies) == 0 {
		// Bare `ok`, matching the branch below: a present-but-empty override means
		// "send it empty", which Values documents as a distinct and useful test.
		// Checking `override != ""` here would honor that test on an operation
		// that declares a body and silently drop it on one that does not.
		if override, ok := vals[ValueKeyBody]; ok {
			ct := vals[ValueKeyContentType]
			if ct == "" && override != "" {
				ct = "application/json"
			}
			return []byte(override), ct
		}
		return nil, ""
	}

	chosen := op.Bodies[0]
	if want := vals[ValueKeyContentType]; want != "" {
		for _, b := range op.Bodies {
			if b.ContentType == want || mediaBase(b.ContentType) == mediaBase(want) {
				chosen = b
				break
			}
		}
	}
	if override, ok := vals[ValueKeyBody]; ok {
		return []byte(override), chosen.ContentType
	}
	return chosen.Content, chosen.ContentType
}

// methodExpectsBody reports whether a method normally carries one, so a
// Content-Length of 0 is still emitted for it.
//
// sj attaches a body only to POST, which is why its own README shows PUT 415
// against the petstore: the server is rejecting an empty body, not the request.
func methodExpectsBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// writeHeader emits one header, dropping it if the document chose a name or
// value that would change the shape of the request.
//
// This is new attack surface the port creates: sj never actually sends its
// "in: header" parameters — they only decorate a printed curl command — so a
// document has never chosen a header name before. An unsanitized one is request
// smuggling into whatever sits behind the proxy.
func writeHeader(buf *bytes.Buffer, name, value string) {
	if !validHeaderName(name) || !validHeaderValue(value) {
		return
	}
	buf.WriteString(name + ": " + value + "\r\n")
}

// validHeaderName checks RFC 7230's token production.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !tokenByte(name[i]) {
			return false
		}
	}
	return true
}

func tokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// validHeaderValue rejects the bytes that would end the line or the header block.
func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\r', '\n', 0:
			return false
		}
	}
	return true
}

// buildCookieHeader folds every cookie into one header.
//
// Values are not percent-encoded wholesale — that would corrupt a legitimate
// base64 session token — so only the bytes that would end the cookie or the
// header are removed.
func buildCookieHeader(cookies []Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		name := strings.TrimSpace(c.Name)
		if name == "" || !validHeaderName(name) {
			continue
		}
		value := strings.Map(func(r rune) rune {
			switch r {
			case ';', ',', '\r', '\n', 0, ' ':
				return -1
			}
			return r
		}, c.Value)
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; ")
}
