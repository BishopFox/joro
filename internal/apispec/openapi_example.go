package apispec

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
)

// generateExample produces a placeholder value for one schema.
//
// The precedence and the per-type values are sj's, so a Joro-generated request
// and an sj-generated request for the same document agree: an explicit example
// wins, then the first enum member, then the first oneOf/anyOf branch, then a
// value chosen by type.
//
// The one addition is "default": a schema that declares one is telling you what
// the server expects, which is strictly better than a synthesized string. sj
// reads default only for Swagger 2 inline parameter types and ignores it inside
// a schema.
func generateExample(node *schemaNode, p Placeholders) any {
	if node == nil {
		return map[string]any{}
	}
	if node.Example != nil {
		return node.Example
	}
	if node.Default != nil {
		return node.Default
	}
	if len(node.Enum) > 0 {
		return node.Enum[0]
	}
	if len(node.OneOf) > 0 {
		return generateExample(node.OneOf[0], p)
	}
	if len(node.AnyOf) > 0 {
		return generateExample(node.AnyOf[0], p)
	}

	switch node.Type {
	case "object", "":
		obj := map[string]any{}
		for _, name := range node.PropertyOrder {
			child := node.Properties[name]
			// The name heuristic applies only where the property actually holds a
			// scalar string. sj applies it to the property name before looking at
			// the schema at all, so an array named "photoUrls" comes out as a bare
			// URL string where the document declares a list — and a server that
			// validates at all answers 400, which tells the operator nothing about
			// whether they were authorized.
			if v, ok := placeholderForName(name, p); ok {
				if isStringish(child) {
					obj[name] = v
					continue
				}
				// A list named for URLs is a list OF URLs: apply the hint to the
				// element so both the shape and the value are right.
				if child != nil && child.Type == "array" && isStringish(child.Items) {
					obj[name] = []any{v}
					continue
				}
			}
			obj[name] = generateExample(child, p)
		}
		if len(obj) == 0 && node.AdditionalProperties != nil {
			obj["additionalProp1"] = generateExample(node.AdditionalProperties, p)
		}
		return obj
	case "array":
		if node.Items != nil {
			return []any{generateExample(node.Items, p)}
		}
		return []any{}
	case "string":
		return stringPlaceholder(node, p)
	case "integer", "number":
		return 1
	case "boolean":
		return true
	default:
		return nil
	}
}

// isStringish reports whether a node holds a plain string, which is the only
// shape a name-based placeholder can legally replace.
func isStringish(node *schemaNode) bool {
	if node == nil {
		return true
	}
	return node.Type == "string" || node.Type == ""
}

// placeholderForName applies sj's property-name heuristics. A property whose
// name mentions a date, a URL or an email gets a value of that shape, because a
// server that validates the field at all will reject "bishopfox" and the
// resulting 400 tells the operator nothing about whether they are authorized.
//
// Matching sj, this runs *before* recursing, so it overrides the property's own
// type. It does not override an explicit example or enum, because those are
// checked first by the caller only for the property's own node — so the order
// here is deliberate and differs from sj, which applies the heuristic to the
// property name before ever looking at the property's schema.
func placeholderForName(name string, p Placeholders) (string, bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "date"):
		return p.Date, true
	case strings.Contains(lower, "email"):
		return p.Email, true
	case strings.Contains(lower, "url"):
		return p.URL, true
	}
	return "", false
}

// stringPlaceholder picks a value for a typed string, preferring a format-shaped
// one. sj returns the test string for every string regardless of format, so a
// field declared as date-time receives "bishopfox".
func stringPlaceholder(node *schemaNode, p Placeholders) string {
	switch node.Format {
	case "date":
		return p.Date
	case "date-time":
		return p.Date + "T00:00:00Z"
	case "email", "idn-email":
		return p.Email
	case "uri", "url", "uri-reference":
		return p.URL
	case "uuid":
		// Deliberately not the test string: a non-UUID here is rejected by format
		// validation before it reaches any authorization decision, so it tests the
		// validator rather than the endpoint.
		return "00000000-0000-4000-8000-000000000000"
	case "byte":
		// The field declares base64-encoded bytes, so the test string has to be
		// encoded to survive the server's decode. It still tracks p.String: an
		// operator who changed the marker needs it recognizable everywhere.
		return base64.StdEncoding.EncodeToString([]byte(p.String))
	case "password":
		return p.String
	}
	return p.String
}

// scalarString renders a generated value for a place that takes one string: a
// path, query, header or cookie parameter.
func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		// A JSON number decodes to float64; emit an integral value without the
		// ".0" a naive format would add, since it usually stands for an id.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, scalarString(item))
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }
