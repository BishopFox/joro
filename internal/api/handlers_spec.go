package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/apiscan"
	"github.com/BishopFox/joro/internal/apispec"
	"github.com/BishopFox/joro/internal/httptools"
)

// specLoadRequest carries a document from one of three sources. Exactly one of
// Raw, Text and URL is used, in that order of preference.
type specLoadRequest struct {
	Raw  string `json:"raw"`  // base64; a captured response, headers included
	Text string `json:"text"` // the document verbatim
	URL  string `json:"url"`  // fetched through Joro's proxy
	Name string `json:"name"`

	// UserAgent is the tab's, when a tab is doing the loading — a discovery
	// sweep probes with it, so the fetch of what it found uses it too. Empty on
	// a first load, where no tab exists yet.
	UserAgent string `json:"userAgent,omitempty"`
}

// handleSpecLoad parses a document and stores it.
func (s *APIServer) handleSpecLoad(w http.ResponseWriter, r *http.Request) {
	var req specLoadRequest
	if err := decodeJSONLimit(r, &req, maxBulkJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var (
		data      []byte
		sourceURL string
	)

	switch {
	case req.Raw != "":
		decoded, err := base64.StdEncoding.DecodeString(req.Raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid raw base64")
			return
		}
		// A captured response arrives with its headers; a pasted document does
		// not. Strip a header block only when one is actually present.
		data = stripHTTPHeaders(decoded)
		sourceURL = req.URL
	case req.Text != "":
		data = []byte(req.Text)
		sourceURL = req.URL
	case req.URL != "":
		fetched, ct, err := s.fetchSpecViaProxy(r, req.URL, req.UserAgent)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		data, sourceURL = fetched, req.URL
		if hint := notADocument(fetched, ct, req.URL); hint != nil {
			writeJSON(w, http.StatusUnprocessableEntity, hint)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "one of raw, text or url is required")
		return
	}

	spec, err := apispec.ParseOpenAPI(data, apispec.Options{SourceURL: sourceURL})
	if err != nil {
		if hint := notADocument(data, "", sourceURL); hint != nil {
			writeJSON(w, http.StatusUnprocessableEntity, hint)
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name != "" {
		spec.Title = req.Name
	}

	s.specStore.Put(spec, data)
	writeJSON(w, http.StatusOK, map[string]any{"spec": spec})
}

// fetchSpecViaProxy retrieves a document through Joro's own proxy, so the fetch
// is captured into History, filtered by scope and routed through SOCKS exactly
// as browser traffic is — and so the document is recoverable later from History
// without re-fetching it.
func (s *APIServer) fetchSpecViaProxy(r *http.Request, rawURL, userAgent string) ([]byte, string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("could not parse %q as a URL", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", fmt.Errorf("URL scheme must be http or https")
	}

	target := u.RequestURI()
	// A load carries no profile, so the tab's User-Agent is the only operator
	// value there is; UserAgentOr falls back for the first load, which has none.
	raw := "GET " + target + " HTTP/1.1\r\nHost: " + u.Host + "\r\n" +
		"User-Agent: " + apispec.UserAgentOr(userAgent) + "\r\n" +
		"Accept: application/json, text/yaml, application/yaml, */*\r\n\r\n"

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// A document is routinely megabytes, so this send asks for a larger read than
	// the default, which is sized for fingerprinting a batch.
	deps := s.specSendDeps()
	deps.MaxRespBytes = maxSpecFetchBytes
	res, err := httptools.SendViaProxy(ctx, []byte(raw), u.Scheme, u.Host, deps)
	if err != nil {
		return nil, "", fmt.Errorf("fetching the document: %v", err)
	}

	body := stripHTTPHeaders(res.RespRaw)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, "", fmt.Errorf("the document URL answered %d", res.StatusCode)
	}

	// The read is still capped. Past the cap the body is truncated and the parse
	// fails with a message about malformed YAML, which sends the operator looking
	// for a problem in the document rather than in how it was fetched.
	if len(body) >= maxSpecFetchBytes-1024 {
		return nil, "", fmt.Errorf(
			"the response was truncated at %d MB, which is the limit for a proxied fetch; "+
				"download the document and load it from a file instead",
			maxSpecFetchBytes/(1<<20))
	}
	return body, contentTypeOf(res.RespRaw), nil
}

// notADocument builds the hint returned when a URL served something that is not
// a description document.
//
// The most common case by far is a Swagger UI page: Joro's own detect rule
// flags those under the same finding as a real document, because its pattern
// matches the string "swagger-ui". Answering "that is the UI, and here is where
// it usually loads its document from" turns the most common failure into the
// next action rather than a dead end.
func notADocument(body []byte, contentType, sourceURL string) map[string]any {
	isHTML := strings.Contains(strings.ToLower(contentType), "text/html") ||
		apispec.LooksLikeHTMLDocument(body)
	if !isHTML {
		return nil
	}

	candidates := apispec.ExtractSpecRefs(body, sourceURL)
	if len(candidates) == 0 {
		for _, p := range apispec.CandidatePaths("", apispec.CandidatePriority) {
			candidates = append(candidates, p)
			if len(candidates) >= 12 {
				break
			}
		}
	}
	return map[string]any{
		"error":       "that URL served an HTML page, not an API description document",
		"kind":        "html",
		"contentType": contentType,
		"sourceUrl":   sourceURL,
		"candidates":  candidates,
	}
}

func (s *APIServer) handleSpecList(w http.ResponseWriter, r *http.Request) {
	type summary struct {
		ID          string    `json:"id"`
		Title       string    `json:"title"`
		Format      string    `json:"format"`
		Version     string    `json:"version"`
		Operations  int       `json:"operations"`
		Servers     int       `json:"servers"`
		Diagnostics int       `json:"diagnostics"`
		SourceURL   string    `json:"sourceUrl,omitempty"`
		SizeBytes   int       `json:"sizeBytes"`
		LoadedAt    time.Time `json:"loadedAt"`
	}
	stored := s.specStore.List()
	out := make([]summary, 0, len(stored))
	for _, sp := range stored {
		out = append(out, summary{
			ID: sp.Spec.ID, Title: sp.Spec.Title, Format: string(sp.Spec.Format),
			Version: sp.Spec.Version, Operations: len(sp.Spec.Operations),
			Servers: len(sp.Spec.Servers), Diagnostics: len(sp.Spec.Diagnostics),
			SourceURL: sp.Spec.SourceURL, SizeBytes: sp.Spec.SizeBytes, LoadedAt: sp.LoadedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"specs": out})
}

func (s *APIServer) handleSpecGet(w http.ResponseWriter, r *http.Request) {
	stored := s.specStore.Get(r.PathValue("id"))
	if stored == nil {
		writeError(w, http.StatusNotFound, "no such document")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"spec": stored.Spec})
}

// handleSpecGetSource returns the original bytes. It is a separate endpoint
// because a document is routinely megabytes and the operator only occasionally
// wants to read it.
func (s *APIServer) handleSpecGetSource(w http.ResponseWriter, r *http.Request) {
	stored := s.specStore.Get(r.PathValue("id"))
	if stored == nil {
		writeError(w, http.StatusNotFound, "no such document")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"source": base64.StdEncoding.EncodeToString(stored.Source),
	})
}

// specPlaceholdersRequest replaces a document's generated values. An absent
// field falls back to the default, so clearing one in the UI restores it.
type specPlaceholdersRequest struct {
	Placeholders apispec.Placeholders `json:"placeholders"`
}

// handleSpecSetPlaceholders re-parses a stored document with new placeholders.
//
// It re-parses rather than patching the Spec in place because a placeholder
// reaches body bytes as well as Param.Default, and no patch reaches both. The
// spec ID is a hash of the source, so the new parse lands under the same ID and
// the auth profiles defined against it survive.
//
// What the operator typed is untouched: Values outranks Param.Default in Render,
// so a hand-edited parameter or body keeps what was entered, including a value
// produced from the previous placeholder. An in-flight run is untouched too —
// selectOperations copies the operations into the run's Config, so a run renders
// the parse it started with.
func (s *APIServer) handleSpecSetPlaceholders(w http.ResponseWriter, r *http.Request) {
	stored := s.specStore.Get(r.PathValue("id"))
	if stored == nil {
		writeError(w, http.StatusNotFound, "no such document")
		return
	}
	var req specPlaceholdersRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	// Rejected here rather than dropped later: a placeholder can become a header
	// parameter's value, and writeHeader silently omits a header whose value
	// carries a control character. The operator would see a missing header with
	// nothing to explain it.
	for name, v := range map[string]string{
		"string": req.Placeholders.String, "date": req.Placeholders.Date,
		"url": req.Placeholders.URL, "email": req.Placeholders.Email,
	} {
		if strings.ContainsAny(v, "\r\n\x00") {
			writeError(w, http.StatusBadRequest,
				"the "+name+" placeholder may not contain a newline or a NUL")
			return
		}
	}

	spec, err := apispec.ParseOpenAPI(stored.Source, apispec.Options{
		SourceURL:    stored.Spec.SourceURL,
		Placeholders: req.Placeholders,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The operator may have renamed the document on load; a re-parse would
	// otherwise revert it to the title the document declares.
	spec.Title = stored.Spec.Title

	s.specStore.Put(spec, stored.Source)
	writeJSON(w, http.StatusOK, map[string]any{"spec": spec})
}

func (s *APIServer) handleSpecDelete(w http.ResponseWriter, r *http.Request) {
	if !s.specStore.Delete(r.PathValue("id")) {
		writeError(w, http.StatusNotFound, "no such document")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// specRenderRequest asks for the exact bytes one operation would send.
type specRenderRequest struct {
	SpecID      string            `json:"specId"`
	OperationID string            `json:"operationId"`
	ServerIndex *int              `json:"serverIndex,omitempty"`
	Scheme      string            `json:"scheme,omitempty"`
	Host        string            `json:"host,omitempty"`
	BasePath    *string           `json:"basePath,omitempty"`
	Values      map[string]string `json:"values,omitempty"`
	ProfileID   string            `json:"profileId,omitempty"`
	UserAgent   string            `json:"userAgent,omitempty"`

	// FuzzParam wraps one parameter's value in FuzzKeyword, for seeding the
	// fuzzer. It is done here rather than by the client searching the rendered
	// bytes, because the value may be percent-encoded, may appear more than
	// once, and may sit inside a JSON body.
	FuzzParam   string `json:"fuzzParam,omitempty"`
	FuzzKeyword string `json:"fuzzKeyword,omitempty"`

	// Omit names parameters to leave out entirely, by ValueKey. Distinct from an
	// empty entry in Values, which means "send it empty".
	Omit []string `json:"omit,omitempty"`
}

func (s *APIServer) handleSpecRender(w http.ResponseWriter, r *http.Request) {
	var req specRenderRequest
	if err := decodeJSONLimit(r, &req, maxBulkJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	op, srv, err := s.resolveOperation(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	auth := s.authForProfile(req.SpecID, req.ProfileID)
	raw, target, err := apispec.Render(op, srv, apispec.Values(req.Values), auth, apispec.RenderOptions{
		UserAgent:  req.UserAgent,
		FuzzParam:  req.FuzzParam,
		FuzzMarker: req.FuzzKeyword,
		Omit:       omitSet(req.Omit),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"raw":    base64.StdEncoding.EncodeToString(raw),
		"scheme": target.Scheme,
		"host":   target.Host,
		"path":   target.Path,
	})
}

// specSendRequest sends one operation. When the operator has not hand-edited the
// bytes the server renders again here rather than trusting a cached render, so a
// stale or in-flight preview can never become the request that goes out.
type specSendRequest struct {
	specRenderRequest
	Raw string `json:"raw,omitempty"` // set only when the operator edited the bytes
}

func (s *APIServer) handleSpecSend(w http.ResponseWriter, r *http.Request) {
	var req specSendRequest
	if err := decodeJSONLimit(r, &req, maxBulkJSONBody); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var (
		raw    []byte
		scheme string
		host   string
	)

	if req.Raw != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid raw base64")
			return
		}
		// Edited bytes go out as written. The profile is deliberately NOT applied
		// on this path: it was already baked in by the render the operator then
		// edited, and applying it again would duplicate the Authorization header.
		raw = decoded
		scheme, host = req.Scheme, req.Host
		if host == "" {
			_, srv, err := s.resolveOperationServer(req.specRenderRequest)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			scheme, host = srv.Scheme, srv.Host
		}
	} else {
		op, srv, err := s.resolveOperation(req.specRenderRequest)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		auth := s.authForProfile(req.SpecID, req.ProfileID)
		rendered, target, err := apispec.Render(op, srv, apispec.Values(req.Values), auth,
			apispec.RenderOptions{UserAgent: req.UserAgent, Omit: omitSet(req.Omit)})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		raw, scheme, host = rendered, target.Scheme, target.Host
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	res, err := httptools.SendViaProxy(ctx, raw, scheme, host, s.specSendDeps())
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sending request: %v", err))
		return
	}

	fp := httptools.FingerprintResponse(res.Seq, res.RespRaw, res.Duration.Milliseconds(), false)
	writeJSON(w, http.StatusOK, map[string]any{
		"raw":        base64.StdEncoding.EncodeToString(raw),
		"rawResp":    base64.StdEncoding.EncodeToString(res.RespRaw),
		"status":     fp.Status,
		"durationMs": res.Duration.Milliseconds(),
		"len":        fp.Len,
		"seq":        res.Seq,
		"requestId":  res.RequestID,
		"seqNote":    res.SeqNote,
		"triage":     apiscan.TriageOf(fp.Status, ""),
		"url":        scheme + "://" + host,
	})
}

// specProfilesRequest replaces the profile set for one document.
type specProfilesRequest struct {
	SpecID   string `json:"specId"`
	Profiles []struct {
		ID          string               `json:"id"`
		Label       string               `json:"label"`
		Rank        int                  `json:"rank"`
		Credentials []apispec.Credential `json:"credentials"`
		Headers     []apispec.Header     `json:"headers"`
		Cookies     []apispec.Cookie     `json:"cookies"`
	} `json:"profiles"`
}

func (s *APIServer) handleSpecSetProfiles(w http.ResponseWriter, r *http.Request) {
	var req specProfilesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.SpecID == "" {
		writeError(w, http.StatusBadRequest, "specId is required")
		return
	}
	if len(req.Profiles) > apiscan.MaxProfiles {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("%d profiles exceeds the limit of %d", len(req.Profiles), apiscan.MaxProfiles))
		return
	}

	profiles := make([]apiscan.Profile, 0, len(req.Profiles))
	for i, p := range req.Profiles {
		id := p.ID
		if id == "" {
			id = fmt.Sprintf("p%d", i)
		}
		profiles = append(profiles, apiscan.Profile{
			ID: id, Label: p.Label, Rank: p.Rank,
			Auth: apispec.Auth{Credentials: p.Credentials, Headers: p.Headers, Cookies: p.Cookies},
		})
	}
	s.specStore.SetProfiles(req.SpecID, profiles)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(profiles)})
}

// handleSpecListProfiles returns profile identity only.
//
// A credential never comes back out. Token create and rotate are the only
// responses in this API that carry a plaintext secret, and an auth profile is
// not one of them.
func (s *APIServer) handleSpecListProfiles(w http.ResponseWriter, r *http.Request) {
	specID := r.URL.Query().Get("specId")
	type summary struct {
		ID       string   `json:"id"`
		Label    string   `json:"label"`
		Rank     int      `json:"rank"`
		Kinds    []string `json:"kinds"`
		HasValue bool     `json:"hasValue"`
		Headers  int      `json:"headers"`
	}
	profiles := s.specStore.Profiles(specID)
	out := make([]summary, 0, len(profiles))
	for _, p := range profiles {
		sum := summary{ID: p.ID, Label: p.Label, Rank: p.Rank, Headers: len(p.Auth.Headers), Kinds: []string{}}
		for _, c := range p.Auth.Credentials {
			sum.Kinds = append(sum.Kinds, string(c.Kind))
			if c.Value != "" || c.Password != "" {
				sum.HasValue = true
			}
		}
		out = append(out, sum)
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

// resolveOperation finds the operation and server a request names.
func (s *APIServer) resolveOperation(req specRenderRequest) (*apispec.Operation, apispec.Server, error) {
	op, srv, err := s.resolveOperationServer(req)
	if err != nil {
		return nil, apispec.Server{}, err
	}
	if op == nil {
		return nil, apispec.Server{}, fmt.Errorf("no operation %q in that document", req.OperationID)
	}
	return op, srv, nil
}

func (s *APIServer) resolveOperationServer(req specRenderRequest) (*apispec.Operation, apispec.Server, error) {
	stored := s.specStore.Get(req.SpecID)
	if stored == nil {
		return nil, apispec.Server{}, fmt.Errorf("no such document")
	}

	var op *apispec.Operation
	for i := range stored.Spec.Operations {
		if stored.Spec.Operations[i].ID == req.OperationID {
			op = &stored.Spec.Operations[i]
			break
		}
	}

	srv := apispec.Server{}
	idx := 0
	if req.ServerIndex != nil {
		idx = *req.ServerIndex
	}
	if idx >= 0 && idx < len(stored.Spec.Servers) {
		srv = stored.Spec.Servers[idx]
	}
	// An operation or its path item may override the document's server, which is
	// how a gateway document addresses several backing services. Honor it only
	// when the operator has not named a host themselves.
	if op != nil && len(op.Servers) > 0 && req.Host == "" {
		srv = op.Servers[0]
	}
	// An explicit scheme/host from the operator always wins: a document may
	// declare none, declare several, or declare one that is wrong.
	if req.Scheme != "" {
		srv.Scheme = req.Scheme
	}
	if req.Host != "" {
		srv.Host = req.Host
	}
	if req.BasePath != nil {
		srv.BasePath = *req.BasePath
	}
	if srv.Host == "" {
		return op, srv, fmt.Errorf("no target host: the document declares no server, so one must be supplied")
	}
	return op, srv, nil
}

// authForProfile returns what a named profile contributes, or nothing.
func (s *APIServer) authForProfile(specID, profileID string) apispec.Auth {
	if profileID == "" {
		return apispec.Auth{}
	}
	for _, p := range s.specStore.Profiles(specID) {
		if p.ID == profileID {
			return p.Auth
		}
	}
	return apispec.Auth{}
}

// specSendDeps assembles what a send needs. Claims is left nil here: these are
// single sends. A run fills in its own.
func (s *APIServer) specSendDeps() httptools.SendDeps {
	return httptools.SendDeps{
		ProxyAddr: fmt.Sprintf("%s:%d", s.cfg.BindAddr, s.cfg.ProxyPort),
		CA:        s.ca,
		Store:     s.store,
	}
}

// stripHTTPHeaders removes a leading HTTP message header block, so a captured
// response can be loaded as a document directly. A body that is not an HTTP
// message is returned unchanged.
func stripHTTPHeaders(raw []byte) []byte {
	if !strings.HasPrefix(string(peek(raw, 16)), "HTTP/") {
		return raw
	}
	if i := strings.Index(string(raw), "\r\n\r\n"); i >= 0 {
		return raw[i+4:]
	}
	if i := strings.Index(string(raw), "\n\n"); i >= 0 {
		return raw[i+2:]
	}
	return raw
}

func contentTypeOf(raw []byte) string {
	head := string(peek(raw, 8192))
	for _, line := range strings.Split(head, "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "content-type") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func peek(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// maxSpecFetchBytes bounds a proxied document fetch. Larger than the default
// send cap because the body here is the product, not a fingerprint: GitHub's
// description document is 13 MB and Stripe's 3.7 MB, and the 2 MB default
// truncated both into a parse error that blamed the document.
const maxSpecFetchBytes = 16 << 20

// omitSet turns the wire's list into the set Render wants.
func omitSet(keys []string) map[string]bool {
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}
