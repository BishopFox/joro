package apispec

import "strings"

// parseAuthSchemes reads both spellings of the security-scheme map.
//
// OpenAPI 3 puts them under components.securitySchemes; Swagger 2 puts them at
// the document root under securityDefinitions, with "basic" as a type rather
// than as a scheme of type "http". sj reads only the OpenAPI 3 spelling, so a
// Swagger 2 document — the format it was written to audit — yields no
// authentication at all.
func parseAuthSchemes(doc map[string]any, format Format) []AuthScheme {
	raw := map[string]any{}
	if format == FormatSwagger2 {
		if m, ok := doc["securityDefinitions"].(map[string]any); ok {
			raw = m
		}
	} else if components, ok := doc["components"].(map[string]any); ok {
		if m, ok := components["securitySchemes"].(map[string]any); ok {
			raw = m
		}
	}

	out := make([]AuthScheme, 0, len(raw))
	for _, name := range sortedKeys(raw) {
		m, ok := raw[name].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, authScheme(name, m))
	}
	return out
}

func authScheme(name string, m map[string]any) AuthScheme {
	s := AuthScheme{
		Name:         name,
		Scheme:       strings.ToLower(stringMember(m, "scheme")),
		BearerFormat: stringMember(m, "bearerFormat"),
		Description:  stringMember(m, "description"),
		Automatable:  true,
	}

	switch strings.ToLower(stringMember(m, "type")) {
	case "basic":
		// Swagger 2 spelling.
		s.Kind = AuthBasic
	case "http":
		switch s.Scheme {
		case "basic":
			s.Kind = AuthBasic
		case "bearer":
			s.Kind = AuthBearer
		default:
			s.Kind = AuthHTTPOther
		}
	case "apikey":
		s.Kind = AuthAPIKey
		s.ParamName = stringMember(m, "name")
		switch strings.ToLower(stringMember(m, "in")) {
		case "query":
			s.In = InQuery
		case "cookie":
			s.In = InCookie
		default:
			s.In = InHeader
		}
		// sj special-cases a scheme whose *key* is literally "bearer" into an
		// Authorization header. That is a guess about one document's naming, not
		// a property of the format: an apiKey scheme says exactly where its value
		// goes, and In/ParamName already carry it.
	case "oauth2":
		s.Kind = AuthOAuth2
		s.Automatable = false
	case "openidconnect":
		s.Kind = AuthOpenID
		s.Automatable = false
	case "mutualtls":
		s.Kind = AuthMutualTLS
		s.Automatable = false
	default:
		s.Kind = AuthHTTPOther
		s.Automatable = false
	}
	return s
}

// parseSecurity reads a security member: a list of alternatives, each naming
// schemes that must all be satisfied.
func parseSecurity(v any) []SecurityRequirement {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]SecurityRequirement, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		req := SecurityRequirement{}
		for _, name := range sortedKeys(m) {
			req.Schemes = append(req.Schemes, name)
			if scopes := stringSlice(m[name]); len(scopes) > 0 {
				if req.Scopes == nil {
					req.Scopes = map[string][]string{}
				}
				req.Scopes[name] = scopes
			}
		}
		if len(req.Schemes) > 0 {
			out = append(out, req)
		}
	}
	return out
}
