package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// Body caps for JSON request bodies, in three tiers.
//
// maxJSONBody is the default, sized above any ordinary control-plane payload.
// maxBulkJSONBody covers the routes carrying base64'd raw requests and responses, and
// wordlists sourced from an upload capped at 50 MB. maxProjectImportBytes covers project
// import, whose body is a whole project snapshot — history, campaigns and findings —
// gzipped and then base64'd, which costs another third.
const (
	maxJSONBody           = 4 << 20
	maxBulkJSONBody       = 64 << 20
	maxProjectImportBytes = 512 << 20
)

// decodeJSON reads a JSON body bounded by maxJSONBody, and requires the
// `application/json` content type.
//
// Unknown fields are accepted rather than rejected, so a client sending a field this build
// does not know still round-trips.
func decodeJSON(r *http.Request, dst any) error {
	return decodeJSONLimit(r, dst, maxJSONBody)
}

// decodeJSONLimit is decodeJSON at an explicit cap, for a route whose payload has its own
// size tier.
func decodeJSONLimit(r *http.Request, dst any, max int64) error {
	if err := requireJSONType(r); err != nil {
		return err
	}
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, max)).Decode(dst)
}

// decodeJSONOptional is decodeJSONLimit for the routes whose body is optional: every field
// defaulting is meaningful, so a request offering no body leaves dst at its zero value
// rather than erroring. A body that is present must still carry the JSON content type.
func decodeJSONOptional(r *http.Request, dst any, max int64) error {
	if r.Body == nil || (r.ContentLength == 0 && r.Header.Get("Content-Type") == "") {
		return nil
	}
	if err := requireJSONType(r); err != nil {
		return err
	}
	err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, max)).Decode(dst)
	if errors.Is(err, io.EOF) {
		return nil // empty body: leave dst at its zero value
	}
	return err
}

func requireJSONType(r *http.Request) error {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" {
		return errors.New("expected Content-Type: application/json")
	}
	return nil
}
