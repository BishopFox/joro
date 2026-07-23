package mythic

import "encoding/base64"

// decodeResponse decodes a Mythic task response. Mythic stores response bytes as
// base64 in the `response` column; if a value isn't valid base64 (older servers or
// already-decoded text) it's returned verbatim.
func decodeResponse(s string) string {
	if s == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return s
}

// encodeBase64 encodes bytes for GraphQL string transport (e.g. file registration).
func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
