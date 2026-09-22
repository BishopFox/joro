package apispec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/url"
	"strings"
)

// parseBodies reads an OpenAPI 3 requestBody into one Body per declared content
// type, in sorted order.
//
// Every content type is kept. sj loops over them and lets the last one a map
// iteration happened to yield win, so a document offering both JSON and
// form-encoded produces a different request on different runs.
func parseBodies(
	doc map[string]any, opMap map[string]any, pointer string,
	p Placeholders, op *Operation, diags *[]Diagnostic,
) {
	reqBody, ok := opMap["requestBody"].(map[string]any)
	if !ok {
		return
	}
	if ref, ok := reqBody["$ref"].(string); ok && ref != "" {
		if !strings.HasPrefix(ref, "#") {
			*diags = append(*diags, Diagnostic{
				Kind: DiagExternalRef, Ref: ref, Pointer: pointer + "/requestBody",
				Detail: "external references are not resolved; only local \"#/...\" pointers are",
			})
			return
		}
		target, found := resolvePointer(doc, ref)
		if !found {
			*diags = append(*diags, Diagnostic{Kind: DiagUnresolvedRef, Ref: ref, Pointer: pointer + "/requestBody"})
			return
		}
		reqBody = target
	}

	// OR, not assign: a Swagger 2 "in: body" or "in: formData" parameter marked
	// required has already run by now, and a v3 requestBody that omits `required`
	// must not clobber it back to false.
	op.BodyRequired = op.BodyRequired || boolMember(reqBody, "required")

	content, ok := reqBody["content"].(map[string]any)
	if !ok {
		return
	}
	for _, ct := range sortedKeys(content) {
		entry, ok := content[ct].(map[string]any)
		if !ok {
			continue
		}
		schema, _ := entry["schema"].(map[string]any)
		node := newExpander(doc, diags).expand(schema, pointer+"/requestBody/content/"+escapePointer(ct))

		// An explicit example on the media type beats anything synthesized from
		// the schema: it is the document telling you what a valid body is.
		if ex, ok := entry["example"]; ok && ex != nil {
			node = &schemaNode{Example: ex}
		}

		body, err := encodeBody(ct, node, p)
		if err != nil {
			*diags = append(*diags, Diagnostic{
				Kind: DiagUnsupported, Ref: ct, Pointer: pointer + "/requestBody",
				Detail: err.Error(),
			})
			continue
		}
		op.Bodies = append(op.Bodies, body)
	}
}

// encodeBody serializes a generated example into one media type's wire form.
func encodeBody(contentType string, node *schemaNode, p Placeholders) (Body, error) {
	example := generateExample(node, p)
	base := mediaBase(contentType)

	switch {
	case base == "application/json" || strings.HasSuffix(base, "+json"):
		raw, err := json.Marshal(example)
		if err != nil {
			return Body{}, fmt.Errorf("body could not be encoded as JSON: %w", err)
		}
		return Body{ContentType: contentType, Encoding: EncJSON, Content: raw, Fields: topLevelFields(example)}, nil

	case base == "application/xml" || base == "text/xml" || strings.HasSuffix(base, "+xml"):
		var buf bytes.Buffer
		writeXML(&buf, "root", example, 0)
		return Body{ContentType: contentType, Encoding: EncXML, Content: buf.Bytes(), Fields: topLevelFields(example)}, nil

	case base == "application/x-www-form-urlencoded":
		obj, ok := example.(map[string]any)
		if !ok {
			return Body{}, fmt.Errorf("form body requires an object schema")
		}
		values := url.Values{}
		for _, k := range sortedKeys(obj) {
			values.Set(k, scalarString(obj[k]))
		}
		return Body{
			ContentType: contentType, Encoding: EncForm,
			Content: []byte(values.Encode()), Fields: topLevelFields(example),
		}, nil

	case base == "multipart/form-data":
		obj, ok := example.(map[string]any)
		if !ok {
			return Body{}, fmt.Errorf("multipart body requires an object schema")
		}
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for _, k := range sortedKeys(obj) {
			if err := mw.WriteField(k, scalarString(obj[k])); err != nil {
				return Body{}, fmt.Errorf("multipart body could not be encoded: %w", err)
			}
		}
		if err := mw.Close(); err != nil {
			return Body{}, fmt.Errorf("multipart body could not be closed: %w", err)
		}
		// The boundary is stored with the bytes it framed, and ContentType carries
		// it. sj serializes with one boundary and then regenerates the header from
		// a fresh writer, so the declared boundary does not frame the body.
		return Body{
			ContentType: mw.FormDataContentType(), Encoding: EncMultipart,
			Content: buf.Bytes(), Fields: topLevelFields(example), Boundary: mw.Boundary(),
		}, nil

	case base == "application/octet-stream":
		return Body{ContentType: contentType, Encoding: EncRaw, Content: []byte(p.String)}, nil

	case strings.HasPrefix(base, "text/"):
		return Body{ContentType: contentType, Encoding: EncRaw, Content: []byte(scalarString(example))}, nil
	}

	// Unknown media type: send the JSON rendering rather than nothing, so the
	// operator has bytes to edit.
	raw, err := json.Marshal(example)
	if err != nil {
		return Body{}, fmt.Errorf("body could not be encoded for %q", contentType)
	}
	return Body{ContentType: contentType, Encoding: EncRaw, Content: raw}, nil
}

func mediaBase(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

func topLevelFields(example any) []string {
	obj, ok := example.(map[string]any)
	if !ok {
		return nil
	}
	return sortedKeys(obj)
}

// appendFormField folds a Swagger 2 "in: formData" parameter into the
// operation's form body, creating it on first use.
func appendFormField(op *Operation, name, value string, required bool) {
	for i := range op.Bodies {
		if op.Bodies[i].Encoding != EncForm {
			continue
		}
		values, err := url.ParseQuery(string(op.Bodies[i].Content))
		if err != nil {
			values = url.Values{}
		}
		values.Set(name, value)
		op.Bodies[i].Content = []byte(values.Encode())
		op.Bodies[i].Fields = append(op.Bodies[i].Fields, name)
		op.BodyRequired = op.BodyRequired || required
		return
	}
	values := url.Values{}
	values.Set(name, value)
	op.Bodies = append(op.Bodies, Body{
		ContentType: "application/x-www-form-urlencoded",
		Encoding:    EncForm,
		Content:     []byte(values.Encode()),
		Fields:      []string{name},
	})
	op.BodyRequired = op.BodyRequired || required
}

// writeXML renders a generated value as XML.
//
// Element names and text are escaped. sj's equivalent escapes neither and emits
// no root element, so a generated value containing "<" produces a body that is
// not XML at all — and here the value can come from a document the target
// controls.
func writeXML(buf *bytes.Buffer, name string, v any, depth int) {
	if depth > 32 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		buf.WriteString("<" + xmlName(name) + ">")
		for _, k := range sortedKeys(t) {
			writeXML(buf, k, t[k], depth+1)
		}
		buf.WriteString("</" + xmlName(name) + ">")
	case []any:
		for _, item := range t {
			writeXML(buf, name, item, depth+1)
		}
	default:
		buf.WriteString("<" + xmlName(name) + ">")
		buf.WriteString(escapeXMLText(scalarString(v)))
		buf.WriteString("</" + xmlName(name) + ">")
	}
}

// xmlName reduces a property name to something that is a legal element name,
// since the name comes from the document.
func xmlName(name string) string {
	var b strings.Builder
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case (r >= '0' && r <= '9' || r == '-' || r == '.') && i > 0:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "field"
	}
	return b.String()
}

func escapeXMLText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}
