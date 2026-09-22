package apispec

import (
	"strconv"
	"strings"
)

// schemaNode is the flattened form of one JSON Schema subtree.
//
// It is unexported and never crosses the API boundary. It exists only to feed
// generateExample; once a value has been produced the tree is dead weight, and
// exporting it would put OpenAPI's vocabulary into a model whose whole claim is
// that it has none. If a per-field body editor is ever wanted, the extension
// point is Body.Fields, not this.
type schemaNode struct {
	Type       string
	Format     string
	Properties map[string]*schemaNode
	// PropertyOrder is sorted, not document order: the document decodes into a
	// map, which has none. Sorted is what matters — it makes a generated body
	// byte-stable across runs, so two renders of one operation can be compared by
	// eye. sj sorts its path and method keys for the same reason, but leaves
	// property iteration to map order, so its generated bodies differ run to run.
	PropertyOrder        []string
	Items                *schemaNode
	Required             map[string]bool
	Enum                 []any
	Example              any
	Default              any
	OneOf                []*schemaNode
	AnyOf                []*schemaNode
	AdditionalProperties *schemaNode
}

// expander carries the budgets across one expansion. sj uses package-level
// state for the equivalent, which is not concurrency-safe; Joro expands several
// documents at once.
type expander struct {
	doc   map[string]any
	depth int
	nodes int
	// active is the reference chain on the *current path*, pushed on entry and
	// popped on exit. sj marks a ref visited and never clears it, so a schema
	// that legitimately names one ref twice as siblings — a billing address and
	// a shipping address, not a cycle at all — silently loses the second to the
	// cycle-break.
	active map[string]bool
	diags  *[]Diagnostic
}

func newExpander(doc map[string]any, diags *[]Diagnostic) *expander {
	return &expander{doc: doc, active: map[string]bool{}, diags: diags}
}

func (e *expander) diag(kind DiagKind, ref, pointer, detail string) {
	if e.diags == nil {
		return
	}
	*e.diags = append(*e.diags, Diagnostic{Kind: kind, Ref: ref, Pointer: pointer, Detail: detail})
}

// emptyObject is what every refusal degrades to: a schema that generates "{}"
// rather than nothing, so a request is still built and still sendable.
func emptyObject() *schemaNode {
	return &schemaNode{Type: "object", Properties: map[string]*schemaNode{}, Required: map[string]bool{}}
}

// expand flattens one schema. Every failure path returns an empty object and
// records a Diagnostic; none of them return an error, because a single
// unresolvable schema must not cost the operator the other forty operations in
// the document.
func (e *expander) expand(schema map[string]any, pointer string) *schemaNode {
	if schema == nil {
		return emptyObject()
	}
	e.nodes++
	if e.nodes > MaxSchemaNodes {
		e.diag(DiagNodeBudget, "", pointer, "schema expansion exceeded the node budget")
		return emptyObject()
	}
	if e.depth > MaxRefDepth {
		e.diag(DiagDepthExceeded, "", pointer, "schema nesting exceeded the depth limit")
		return emptyObject()
	}

	if ref, ok := schema["$ref"].(string); ok && ref != "" {
		return e.expandRef(ref, pointer)
	}

	node := &schemaNode{
		Properties: map[string]*schemaNode{},
		Required:   map[string]bool{},
	}
	if t, ok := schema["type"].(string); ok {
		node.Type = t
	} else if types, ok := schema["type"].([]any); ok {
		// OpenAPI 3.1 allows a type array, commonly ["string","null"]. Take the
		// first non-null member; sj reads only the string form and silently
		// treats the whole schema as untyped.
		for _, t := range types {
			if s, ok := t.(string); ok && s != "null" {
				node.Type = s
				break
			}
		}
	}
	if f, ok := schema["format"].(string); ok {
		node.Format = f
	}
	if enum, ok := schema["enum"].([]any); ok {
		node.Enum = enum
	}
	if ex, ok := schema["example"]; ok && ex != nil {
		node.Example = ex
	}
	if def, ok := schema["default"]; ok && def != nil {
		node.Default = def
	}
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			if name, ok := r.(string); ok {
				node.Required[name] = true
			}
		}
	}

	e.depth++
	defer func() { e.depth-- }()

	if props, ok := schema["properties"].(map[string]any); ok {
		for _, name := range sortedKeys(props) {
			if m, ok := props[name].(map[string]any); ok {
				node.Properties[name] = e.expand(m, pointer+"/properties/"+escapePointer(name))
				node.PropertyOrder = append(node.PropertyOrder, name)
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		node.Items = e.expand(items, pointer+"/items")
	}
	if ap, ok := schema["additionalProperties"].(map[string]any); ok {
		node.AdditionalProperties = e.expand(ap, pointer+"/additionalProperties")
	}

	// allOf merges INTO this node rather than replacing it.
	//
	// sj builds a fresh {Type:"object"} holding only Properties and Required and
	// returns it immediately, which drops Type, Enum, Example, Items and
	// AdditionalProperties from both this schema and every branch, and discards
	// any sibling "properties" declared alongside the allOf. An allOf wrapping a
	// $ref to a string enum comes out of sj as an empty object.
	if allOf, ok := schema["allOf"].([]any); ok {
		for i, entry := range allOf {
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			sub := e.expand(m, pointer+"/allOf/"+itoa(i))
			for name, v := range sub.Properties {
				if _, exists := node.Properties[name]; !exists {
					node.PropertyOrder = append(node.PropertyOrder, name)
				}
				node.Properties[name] = v
			}
			for name := range sub.Required {
				node.Required[name] = true
			}
			if node.Type == "" {
				node.Type = sub.Type
			}
			if node.Example == nil {
				node.Example = sub.Example
			}
			if node.Items == nil {
				node.Items = sub.Items
			}
			if len(node.Enum) == 0 {
				node.Enum = sub.Enum
			}
			if node.AdditionalProperties == nil {
				node.AdditionalProperties = sub.AdditionalProperties
			}
		}
		if node.Type == "" && len(node.Properties) > 0 {
			node.Type = "object"
		}
	}

	for _, key := range []string{"oneOf", "anyOf"} {
		branches, ok := schema[key].([]any)
		if !ok {
			continue
		}
		for i, entry := range branches {
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			sub := e.expand(m, pointer+"/"+key+"/"+itoa(i))
			if key == "oneOf" {
				node.OneOf = append(node.OneOf, sub)
			} else {
				node.AnyOf = append(node.AnyOf, sub)
			}
		}
	}

	return node
}

// expandRef resolves a local pointer and expands what it names.
func (e *expander) expandRef(ref, pointer string) *schemaNode {
	if !strings.HasPrefix(ref, "#") {
		// Refused, not attempted. See the package doc: the document is
		// attacker-controlled and the value read would be rendered into a body
		// and sent to a host the same document chose.
		e.diag(DiagExternalRef, ref, pointer,
			"external references are not resolved; only local \"#/...\" pointers are")
		return emptyObject()
	}
	if e.active[ref] {
		e.diag(DiagRefCycle, ref, pointer, "reference cycle broken")
		return emptyObject()
	}

	target, ok := resolvePointer(e.doc, ref)
	if !ok {
		e.diag(DiagUnresolvedRef, ref, pointer, "reference does not resolve within the document")
		return emptyObject()
	}

	e.active[ref] = true
	defer delete(e.active, ref)

	e.depth++
	defer func() { e.depth-- }()

	return e.expand(target, ref)
}

// resolvePointer walks a local JSON pointer ("#/components/schemas/Pet").
//
// Segments are unescaped per RFC 6901 before each lookup. sj skips that, so any
// reference into a path-keyed map — "#/paths/~1pets/get" — resolves to nothing,
// silently, which is the whole class of reference a Swagger 2 document uses for
// shared parameters.
func resolvePointer(doc map[string]any, ref string) (map[string]any, bool) {
	body := strings.TrimPrefix(ref, "#")
	body = strings.TrimPrefix(body, "/")
	if body == "" {
		return nil, false
	}
	segments := strings.Split(body, "/")
	if len(segments) > MaxPointerSegments {
		return nil, false
	}

	var cur any = doc
	for _, seg := range segments {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[unescapePointer(seg)]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			// A pointer segment against an array is an index. This is how a $ref
			// into a shared "parameters" array is written, so without it the most
			// common cross-document reference in a hand-written spec resolves to
			// nothing.
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	out, ok := cur.(map[string]any)
	return out, ok
}

// unescapePointer decodes RFC 6901's two escapes. Order matters: ~1 first, then
// ~0, or an encoded "~1" would be decoded twice.
func unescapePointer(seg string) string {
	seg = strings.ReplaceAll(seg, "~1", "/")
	return strings.ReplaceAll(seg, "~0", "~")
}

// escapePointer is the inverse, used to build the Pointer on a Diagnostic. Order
// is the mirror of unescapePointer: ~0 first.
func escapePointer(seg string) string {
	seg = strings.ReplaceAll(seg, "~", "~0")
	return strings.ReplaceAll(seg, "/", "~1")
}
