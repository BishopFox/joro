package apispec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// httpMethods are the path-item members that name an operation.
//
// This whitelist is why a path-level "parameters" member cannot be mistaken for
// a method. sj derives its method list from the path item's keys and filters
// only "delete" and "patch", so a path that declares shared parameters — a very
// common shape — yields a bogus operation with the method PARAMETERS, and the
// shared parameters are never applied to the real operations either.
var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

func isHTTPMethod(s string) bool {
	for _, m := range httpMethods {
		if s == m {
			return true
		}
	}
	return false
}

// ParseOpenAPI parses a Swagger 2.0 or OpenAPI 3.x document.
//
// An error means the input is not a document at all. Everything survivable is a
// Diagnostic on the returned Spec — see the package doc.
func ParseOpenAPI(data []byte, opts Options) (*Spec, error) {
	if unwrapped, ok := UnwrapJSSpec(data); ok {
		data = unwrapped
	}

	doc, diags, err := decodeDocument(data)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	spec := &Spec{
		ID:          hex.EncodeToString(sum[:8]),
		SourceURL:   opts.SourceURL,
		SizeBytes:   len(data),
		Diagnostics: diags,
	}

	switch {
	case strings.HasPrefix(stringMember(doc, "openapi"), "3"):
		spec.Format = FormatOpenAPI3
		spec.Version = stringMember(doc, "openapi")
	case strings.HasPrefix(stringMember(doc, "swagger"), "2"):
		spec.Format = FormatSwagger2
		spec.Version = stringMember(doc, "swagger")
	default:
		return nil, fmt.Errorf("not an OpenAPI or Swagger document: no recognized \"openapi\" or \"swagger\" version member")
	}

	if info, ok := doc["info"].(map[string]any); ok {
		spec.Title = stringMember(info, "title")
		spec.Description = stringMember(info, "description")
		spec.APIVersion = stringMember(info, "version")
	}
	if spec.Title == "" {
		spec.Title = "Untitled API"
	}

	spec.Servers = parseServers(doc, spec.Format, opts.SourceURL, &spec.Diagnostics)
	spec.Auth = parseAuthSchemes(doc, spec.Format)
	spec.Security = parseSecurity(doc["security"])

	p := opts.Placeholders.withDefaults()
	spec.Placeholders = p
	spec.Operations = parseOperations(doc, p, opts.DestructiveWhitelist, &spec.Diagnostics)

	spec.normalize()
	return spec, nil
}

// parseServers reads both spellings.
//
// Every declared server is kept. sj takes servers[0] and dies telling the
// operator to pass -T when there is more than one; here the ambiguity is handed
// to the operator as a choice, because picking silently is how a scan ends up
// aimed at a host nobody read.
func parseServers(doc map[string]any, format Format, sourceURL string, diags *[]Diagnostic) []Server {
	var out []Server

	if format == FormatSwagger2 {
		host := stringMember(doc, "host")
		basePath := normalizeBasePath(stringMember(doc, "basePath"))
		scheme := ""
		if schemes, ok := doc["schemes"].([]any); ok && len(schemes) > 0 {
			// Prefer https when the document offers it: a scan that silently
			// downgrades to http is one that puts the operator's credentials on
			// the wire in clear.
			for _, s := range schemes {
				if str, ok := s.(string); ok && str == "https" {
					scheme = "https"
					break
				}
			}
			if scheme == "" {
				if str, ok := schemes[0].(string); ok {
					scheme = str
				}
			}
		}
		if host != "" {
			if scheme == "" {
				scheme = schemeFromSource(sourceURL, "https")
			}
			out = append(out, Server{
				URL: scheme + "://" + host + basePath, Scheme: scheme, Host: host, BasePath: basePath,
			})
		} else if base := serverFromSource(sourceURL, basePath); base != nil {
			out = append(out, *base)
		}
		return out
	}

	out = append(out, parseServerEntries(doc["servers"], sourceURL, "/servers", diags)...)

	if len(out) == 0 {
		if base := serverFromSource(sourceURL, ""); base != nil {
			out = append(out, *base)
		}
	}
	return out
}

// parseServerList reads a servers member that is not the document's own — a path
// item's or an operation's. It resolves nothing against a source URL, because an
// override only makes sense as an absolute address; a relative one would mean
// the same thing as the document default and is reported instead.
func parseServerList(v any, pointer string, diags *[]Diagnostic) []Server {
	return parseServerEntries(v, "", pointer, diags)
}

// parseServerEntries turns an OpenAPI 3 servers array into Servers.
func parseServerEntries(v any, sourceURL, pointer string, diags *[]Diagnostic) []Server {
	servers, _ := v.([]any)
	var out []Server
	for _, entry := range servers {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		raw := stringMember(m, "url")
		if raw == "" {
			continue
		}
		vars := serverVars(m)
		resolved := substituteServerVars(raw, vars)

		srv := Server{URL: raw, Description: stringMember(m, "description"), Vars: vars}
		if strings.Contains(resolved, "://") {
			u, err := url.Parse(resolved)
			if err != nil || u.Host == "" {
				*diags = append(*diags, Diagnostic{
					Kind: DiagMalformed, Ref: raw, Pointer: pointer,
					Detail: "server URL could not be parsed",
				})
				continue
			}
			srv.Scheme, srv.Host, srv.BasePath = u.Scheme, u.Host, normalizeBasePath(u.Path)
		} else {
			// A relative server URL is a base path against wherever the document
			// was served from. sj dies here unless -T was passed.
			srv.BasePath = normalizeBasePath(resolved)
			if base := serverFromSource(sourceURL, srv.BasePath); base != nil {
				srv.Scheme, srv.Host = base.Scheme, base.Host
			}
			if srv.Host == "" && sourceURL == "" && pointer != "/servers" {
				// An override with no host resolves to the document default, so it
				// is not an override at all. Say so rather than shipping a server
				// that silently cannot be dialed.
				*diags = append(*diags, Diagnostic{
					Kind: DiagUnsupported, Ref: raw, Pointer: pointer,
					Detail: "relative server override ignored; it names no host of its own",
				})
				continue
			}
		}
		out = append(out, srv)
	}
	return out
}

func serverVars(m map[string]any) map[string]string {
	raw, ok := m["variables"].(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for name, v := range raw {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		// scalarString, not stringMember: a default is routinely a number
		// ({port}), which a string assertion reads as absent — leaving "{port}"
		// in the URL, which url.Parse rejects, dropping the only server.
		if def := scalarString(vm["default"]); def != "" {
			out[name] = def
			continue
		}
		if enum, ok := vm["enum"].([]any); ok && len(enum) > 0 {
			out[name] = scalarString(enum[0])
		}
	}
	return out
}

func substituteServerVars(raw string, vars map[string]string) string {
	for name, val := range vars {
		raw = strings.ReplaceAll(raw, "{"+name+"}", val)
	}
	return raw
}

// serverFromSource derives an origin from wherever the document was fetched.
func serverFromSource(sourceURL, basePath string) *Server {
	if sourceURL == "" {
		return nil
	}
	u, err := url.Parse(sourceURL)
	if err != nil || u.Host == "" {
		return nil
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &Server{
		URL: scheme + "://" + u.Host + basePath, Scheme: scheme, Host: u.Host, BasePath: basePath,
		Description: "derived from where the document was served",
	}
}

func schemeFromSource(sourceURL, fallback string) string {
	if u, err := url.Parse(sourceURL); err == nil && u.Scheme != "" {
		return u.Scheme
	}
	return fallback
}

// normalizeBasePath trims to "" or "/segment", never a trailing slash.
func normalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

// parseOperations walks paths x methods.
//
// Paths and methods are both visited in sorted order so a document always yields
// the same operation list, which is what lets two runs be compared.
func parseOperations(doc map[string]any, p Placeholders, whitelist []string, diags *[]Diagnostic) []Operation {
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		*diags = append(*diags, Diagnostic{Kind: DiagMalformed, Pointer: "/paths", Detail: "document declares no paths"})
		return nil
	}

	var out []Operation
	truncated := false

	// seenIDs uniquifies operation ids. A document is not supposed to repeat an
	// operationId, but code generators emit duplicates routinely, and every
	// lookup downstream — the draft the operator is editing, the checkbox set,
	// and both server-side resolvers — keys on it and takes the first match. A
	// collision there does not merely confuse the tree; it renders and sends the
	// wrong operation's bytes.
	seenIDs := map[string]int{}

	for _, path := range sortedKeys(paths) {
		item, ok := paths[path].(map[string]any)
		if !ok {
			continue
		}
		// A path item may itself be a $ref.
		if ref, ok := item["$ref"].(string); ok && ref != "" {
			target, found := resolvePointer(doc, ref)
			if !found {
				kind := DiagUnresolvedRef
				if !strings.HasPrefix(ref, "#") {
					kind = DiagExternalRef
				}
				*diags = append(*diags, Diagnostic{Kind: kind, Ref: ref, Pointer: "/paths/" + escapePointer(path)})
				continue
			}
			item = target
		}

		// Path-level parameters apply to every operation on the path, and an
		// operation-level parameter of the same name+in overrides one.
		sharedRaw, _ := item["parameters"].([]any)
		// A path item may also override the server for every operation on it.
		sharedServers := parseServerList(item["servers"], "/paths/"+escapePointer(path), diags)

		for _, method := range sortedKeys(item) {
			if !isHTTPMethod(strings.ToLower(method)) {
				continue
			}
			opMap, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			if len(out) >= MaxOperations {
				truncated = true
				break
			}
			op := parseOperation(doc, path, strings.ToUpper(method), opMap, sharedRaw, p, whitelist, diags)
			if len(op.Servers) == 0 {
				op.Servers = sharedServers
			}
			op.ID = uniqueID(op.ID, seenIDs, &op, diags)
			out = append(out, op)
		}
		if truncated {
			break
		}
	}

	if truncated {
		*diags = append(*diags, Diagnostic{
			Kind: DiagTruncated, Pointer: "/paths",
			Detail: fmt.Sprintf("stopped after %d operations", MaxOperations),
		})
	}
	if len(out) == 0 {
		// Silence here would be worse than the empty list: the operator sees a
		// document that loaded cleanly and lists nothing, with no reason given.
		*diags = append(*diags, Diagnostic{
			Kind: DiagMalformed, Pointer: "/paths",
			Detail: "the document declares no operations",
		})
	}
	return out
}

// uniqueID makes an operation id unique within the document, reporting any
// collision it had to resolve.
func uniqueID(id string, seen map[string]int, op *Operation, diags *[]Diagnostic) string {
	n, clash := seen[id]
	seen[id] = n + 1
	if !clash {
		return id
	}
	unique := fmt.Sprintf("%s#%d", id, n)
	d := Diagnostic{
		Kind: DiagDuplicateKey, Ref: id,
		Pointer: "/paths/" + escapePointer(op.Path) + "/" + strings.ToLower(op.Method),
		Detail:  "duplicate operationId; this one is addressed as " + unique,
	}
	*diags = append(*diags, d)
	op.Diagnostics = append(op.Diagnostics, d)
	return unique
}

func parseOperation(
	doc map[string]any, path, method string, opMap map[string]any,
	sharedParams []any, p Placeholders, whitelist []string, specDiags *[]Diagnostic,
) Operation {
	pointer := "/paths/" + escapePointer(path) + "/" + strings.ToLower(method)

	op := Operation{
		Method:      method,
		Path:        path,
		Summary:     stringMember(opMap, "summary"),
		Description: stringMember(opMap, "description"),
		Deprecated:  boolMember(opMap, "deprecated"),
		Responses:   map[string]string{},
	}
	op.ID = operationID(opMap, method, path)
	op.Tags = stringSlice(opMap["tags"])
	op.Servers = parseServerList(opMap["servers"], pointer+"/servers", specDiags)

	if sec, ok := opMap["security"]; ok {
		// A present-but-empty security member is an explicit opt out of
		// authentication, which is not the same as inheriting the document's.
		op.Security = parseSecurity(sec)
		if op.Security == nil {
			op.Security = []SecurityRequirement{}
		}
	}

	if resp, ok := opMap["responses"].(map[string]any); ok {
		for _, code := range sortedKeys(resp) {
			m, ok := resp[code].(map[string]any)
			if !ok {
				continue
			}
			// Keyed by the document's own spelling. sj stores these under an int
			// key and looks them up with one too, but builds the map from string
			// keys, so the description never resolves.
			op.Responses[code] = stringMember(m, "description")
		}
	}

	pathPointer := "/paths/" + escapePointer(path)
	merged := mergeParams(doc, sharedParams, opMap["parameters"], pathPointer, pointer)
	opDiags := &op.Diagnostics
	for _, mp := range merged {
		m, ok := mp.raw.(map[string]any)
		if !ok {
			continue
		}
		m = derefParam(doc, m, mp.pointer, opDiags)
		if m == nil {
			continue
		}
		parseParam(doc, m, mp.pointer, p, &op, opDiags)
	}

	parseBodies(doc, opMap, pointer, p, &op, opDiags)

	op.Destructive, op.DestructiveReasons = Classify(method, path, op.ID, op.Summary, whitelist)

	*specDiags = append(*specDiags, op.Diagnostics...)
	return op
}

// mergedParam is one parameter plus the pointer to where it was actually
// written. The pointer travels with it because a path-level parameter and an
// operation-level one end up in the same list: indexing that list would make
// every diagnostic on a shared parameter name a location it does not occupy,
// and pointing at the wrong place is worse than saying nothing.
type mergedParam struct {
	raw     any
	pointer string
}

// mergeParams overlays operation parameters onto path-level ones, keyed by
// name+in as the specification requires.
func mergeParams(doc map[string]any, shared, own any, pathPointer, opPointer string) []mergedParam {
	sharedList, _ := shared.([]any)
	ownList, _ := own.([]any)

	ownMerged := make([]mergedParam, 0, len(ownList))
	for i, raw := range ownList {
		ownMerged = append(ownMerged, mergedParam{raw, fmt.Sprintf("%s/parameters/%d", opPointer, i)})
	}
	if len(sharedList) == 0 {
		return ownMerged
	}

	taken := map[string]bool{}
	for _, raw := range ownList {
		if m, ok := raw.(map[string]any); ok {
			m = derefParamQuiet(doc, m)
			taken[stringMember(m, "name")+"\x00"+stringMember(m, "in")] = true
		}
	}

	out := make([]mergedParam, 0, len(sharedList)+len(ownList))
	for i, raw := range sharedList {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		d := derefParamQuiet(doc, m)
		if taken[stringMember(d, "name")+"\x00"+stringMember(d, "in")] {
			continue
		}
		out = append(out, mergedParam{raw, fmt.Sprintf("%s/parameters/%d", pathPointer, i)})
	}
	return append(out, ownMerged...)
}

func derefParam(doc map[string]any, m map[string]any, pointer string, diags *[]Diagnostic) map[string]any {
	ref, ok := m["$ref"].(string)
	if !ok || ref == "" {
		return m
	}
	if !strings.HasPrefix(ref, "#") {
		*diags = append(*diags, Diagnostic{
			Kind: DiagExternalRef, Ref: ref, Pointer: pointer,
			Detail: "external references are not resolved; only local \"#/...\" pointers are",
		})
		return nil
	}
	target, found := resolvePointer(doc, ref)
	if !found {
		*diags = append(*diags, Diagnostic{Kind: DiagUnresolvedRef, Ref: ref, Pointer: pointer})
		return nil
	}
	return target
}

// firstMediaType picks one entry from a content map, in sorted order so the
// choice is stable across runs.
func firstMediaType(v any) (string, map[string]any, bool) {
	content, ok := v.(map[string]any)
	if !ok || len(content) == 0 {
		return "", nil, false
	}
	for _, ct := range sortedKeys(content) {
		if m, ok := content[ct].(map[string]any); ok {
			return ct, m, true
		}
	}
	return "", nil, false
}

// encodedMediaValue renders a parameter whose value is a whole media type.
func encodedMediaValue(contentType string, node *schemaNode, p Placeholders) string {
	body, err := encodeBody(contentType, node, p)
	if err != nil {
		return scalarString(generateExample(node, p))
	}
	return string(body.Content)
}

func derefParamQuiet(doc map[string]any, m map[string]any) map[string]any {
	if ref, ok := m["$ref"].(string); ok && strings.HasPrefix(ref, "#") {
		if target, found := resolvePointer(doc, ref); found {
			return target
		}
	}
	return m
}

// parseParam turns one parameter into zero or more Params, or into a Body for
// the Swagger 2 "in: body" and "in: formData" forms.
func parseParam(
	doc map[string]any, m map[string]any, pointer string,
	p Placeholders, op *Operation, diags *[]Diagnostic,
) {
	name := stringMember(m, "name")
	in := strings.ToLower(stringMember(m, "in"))
	if name == "" && in != "body" {
		return
	}

	switch in {
	case "body":
		// Swagger 2 carries the request body as a parameter.
		schema, _ := m["schema"].(map[string]any)
		node := newExpander(doc, diags).expand(schema, pointer+"/schema")
		body, err := encodeBody("application/json", node, p)
		if err == nil {
			op.Bodies = append(op.Bodies, body)
			op.BodyRequired = op.BodyRequired || boolMember(m, "required")
		}
		return
	case "formdata":
		appendFormField(op, name, paramDefault(doc, m, pointer, p, diags), boolMember(m, "required"))
		return
	}

	pin := ParamIn(in)
	switch pin {
	case InPath, InQuery, InHeader, InCookie:
	default:
		*diags = append(*diags, Diagnostic{
			Kind: DiagUnsupported, Ref: in, Pointer: pointer,
			Detail: "parameter location is not one of path, query, header, cookie",
		})
		return
	}

	base := Param{
		Name:        name,
		In:          pin,
		Required:    boolMember(m, "required") || pin == InPath,
		Deprecated:  boolMember(m, "deprecated"),
		Description: stringMember(m, "description"),
		Style:       stringMember(m, "style"),
	}
	// The default style depends on where the parameter lives: form for query and
	// cookie, simple for path and header. Treating an unset style as form
	// everywhere would be wrong for half of them — and flagging the spec's own
	// default as unsupported is how a corpus run produced 347 diagnostics against
	// Stripe for parameters that were serialized perfectly correctly.
	if base.Style == "" {
		base.Style = defaultStyleFor(pin)
	}
	if ex, ok := m["explode"].(bool); ok {
		base.Explode = ex
	} else {
		// form defaults to explode:true; every other style defaults to false.
		base.Explode = base.Style == StyleForm
	}
	switch base.Style {
	case StyleForm, StyleSimple, StyleDeepObject, StyleSpaceDelimited, StylePipeDelimited:
	default:
		// matrix and label are path-only and genuinely unhandled.
		*diags = append(*diags, Diagnostic{
			Kind: DiagUnsupported, Ref: base.Style, Pointer: pointer,
			Detail: "parameter style is not supported; it is serialized as " + defaultStyleFor(pin),
		})
		base.Style = defaultStyleFor(pin)
	}

	schema, hasSchema := m["schema"].(map[string]any)
	if !hasSchema {
		// OpenAPI 3 lets a parameter carry `content` instead of `schema`, which is
		// the documented way to send a structured value in a query or header. It
		// has no inline type, so falling through to the Swagger 2 branch below
		// would silently yield an untyped parameter valued "1" and discard the
		// schema the document actually supplied.
		if ct, mediaType, ok := firstMediaType(m["content"]); ok {
			if inner, ok := mediaType["schema"].(map[string]any); ok {
				node := newExpander(doc, diags).expand(inner, pointer+"/content/"+escapePointer(ct)+"/schema")
				base.Type = node.Type
				base.Format = node.Format
				base.Enum = stringEnum(node.Enum)
				base.ContentType = ct
				// A structured value in a parameter is serialized as the media type,
				// not exploded, so it goes on the wire as one opaque string.
				base.Default = encodedMediaValue(ct, node, p)
				op.Params = append(op.Params, base)
				return
			}
			*diags = append(*diags, Diagnostic{
				Kind: DiagUnsupported, Ref: ct, Pointer: pointer + "/content",
				Detail: "parameter declares content with no schema; a placeholder was generated",
			})
		}

		// Swagger 2 spells the type inline on the parameter.
		base.Type = stringMember(m, "type")
		base.Format = stringMember(m, "format")
		base.Enum = stringEnum(m["enum"])
		base.Default = inlineDefault(m, base, p)
		op.Params = append(op.Params, base)
		return
	}

	node := newExpander(doc, diags).expand(schema, pointer+"/schema")
	base.Type = node.Type
	base.Format = node.Format
	base.Enum = stringEnum(node.Enum)

	// An object-schema query parameter is sent as one parameter per property,
	// so it is presented that way too — otherwise the operator edits a shape
	// that never goes on the wire.
	if pin == InQuery && node.Type == "object" && len(node.PropertyOrder) > 0 {
		for _, prop := range node.PropertyOrder {
			child := node.Properties[prop]
			op.Params = append(op.Params, Param{
				Name:         prop,
				In:           InQuery,
				Required:     node.Required[prop],
				Description:  base.Description,
				Type:         child.Type,
				Format:       child.Format,
				Enum:         stringEnum(child.Enum),
				Default:      scalarString(generateExample(child, p)),
				ExplodedFrom: name,
				Style:        base.Style,
				Explode:      base.Explode,
			})
		}
		return
	}

	base.Default = scalarString(generateExample(node, p))
	if base.Default == "" && base.Type == "string" {
		base.Default = versionAwareString(name, p)
	}
	op.Params = append(op.Params, base)
}

// inlineDefault picks a value for a Swagger 2 inline-typed parameter.
func inlineDefault(m map[string]any, base Param, p Placeholders) string {
	if def, ok := m["default"]; ok && def != nil {
		return scalarString(def)
	}
	if ex, ok := m["example"]; ok && ex != nil {
		return scalarString(ex)
	}
	if len(base.Enum) > 0 {
		return base.Enum[0]
	}
	switch base.Type {
	case "string":
		if v, ok := placeholderForName(base.Name, p); ok {
			return v
		}
		return versionAwareString(base.Name, p)
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "array":
		// A Swagger 2 array parameter carries its element schema inline, and that
		// is where an enum or a default lives. sj looks only at the element type
		// and otherwise emits the test string, so petstore's findByStatus — whose
		// items declare enum [available, pending, sold] and default "available" —
		// is queried for a status of "bishopfox".
		items, ok := m["items"].(map[string]any)
		if !ok {
			return p.String
		}
		if def, ok := items["default"]; ok && def != nil {
			return scalarString(def)
		}
		if enum := stringEnum(items["enum"]); len(enum) > 0 {
			return enum[0]
		}
		switch stringMember(items, "type") {
		case "integer", "number":
			return "1"
		case "boolean":
			return "true"
		}
		if v, ok := placeholderForName(base.Name, p); ok {
			return v
		}
		return p.String
	}
	return "1"
}

// versionAwareString keeps one of sj's heuristics: a parameter named for an API
// version gets "1" rather than the test string, because "bishopfox" in a version
// segment 404s and the operator learns nothing about authorization. The narrower
// spelling here is only reached when the document supplies no example, enum or
// default, which now covers most version parameters on its own.
func versionAwareString(name string, p Placeholders) string {
	lower := strings.ToLower(name)
	if lower == "version" || strings.HasSuffix(lower, "version") {
		return "1"
	}
	return p.String
}

func paramDefault(doc map[string]any, m map[string]any, pointer string, p Placeholders, diags *[]Diagnostic) string {
	if schema, ok := m["schema"].(map[string]any); ok {
		node := newExpander(doc, diags).expand(schema, pointer+"/schema")
		return scalarString(generateExample(node, p))
	}
	base := Param{Name: stringMember(m, "name"), Type: stringMember(m, "type"), Enum: stringEnum(m["enum"])}
	return inlineDefault(m, base, p)
}

// operationID prefers the document's own operationId and falls back to a stable
// method:path form.
func operationID(opMap map[string]any, method, path string) string {
	if id := stringMember(opMap, "operationId"); id != "" {
		return id
	}
	return strings.ToLower(method) + ":" + path
}

func stringMember(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func boolMember(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringEnum(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, scalarString(item))
	}
	return out
}
