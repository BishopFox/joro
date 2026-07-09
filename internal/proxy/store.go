package proxy

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScopeFunc checks whether a request with the given host, method, and path is in scope.
type ScopeFunc func(host, method, path string) bool

// CapturedRequest holds all data about a proxied HTTP request/response pair.
type CapturedRequest struct {
	ID           string        `json:"id"`
	Seq          int           `json:"seq"`
	Timestamp    time.Time     `json:"timestamp"`
	Method       string        `json:"method"`
	URL          string        `json:"url"`
	Host         string        `json:"host"`
	Protocol     string        `json:"protocol,omitempty"` // "HTTP/1.1" | "HTTP/2"
	StatusCode   int           `json:"statusCode"`
	ContentType  string        `json:"contentType,omitempty"`
	Duration     time.Duration `json:"duration"`
	ResponseSize int           `json:"responseSize"`
	ReqRaw       []byte        `json:"reqRaw,omitempty"`
	RespRaw      []byte        `json:"respRaw,omitempty"`
}

// RequestFilter holds optional filter criteria for listing requests.
type RequestFilter struct {
	Host         string
	Method       string
	Status       int
	Search       string
	Exclude      string    // comma-separated file extensions, e.g. ".css,.png,.jpg"
	ExtMode      string    // "exclude" (default) or "include"
	ContentType  string    // simplified content type keyword, e.g. "html", "json", "image"
	Content      string    // string/regex matched against raw request+response bytes
	ContentMode  string    // "include" (default) or "exclude"
	ContentRegex bool      // treat Content as a regular expression
	InScopeFunc  ScopeFunc // optional: if set, only include requests passing this check
	Offset       int
	Limit        int
}

// Store is a thread-safe in-memory ring buffer of captured requests.
type Store struct {
	mu      sync.RWMutex
	items   []*CapturedRequest
	maxSize int
	nextSeq int
}

// NewStore creates a Store with the given max capacity (default 5,000).
func NewStore(maxSize int) *Store {
	if maxSize <= 0 {
		maxSize = 5000
	}
	return &Store{
		items:   make([]*CapturedRequest, 0, 256),
		maxSize: maxSize,
	}
}

// Add appends a request, evicting the oldest if at capacity.
func (s *Store) Add(r *CapturedRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSeq++
	r.Seq = s.nextSeq
	if len(s.items) >= s.maxSize {
		s.items = s.items[1:]
	}
	s.items = append(s.items, r)
}

// Get returns the request with the given ID, or nil.
func (s *Store) Get(id string) *CapturedRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.items {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// contentTypeKeywords maps simplified keywords to MIME substrings.
var contentTypeKeywords = map[string]string{
	"html":       "text/html",
	"json":       "json",
	"js":         "javascript",
	"javascript": "javascript",
	"xml":        "xml",
	"css":        "text/css",
	"image":      "image/",
	"font":       "font/",
	"text":       "text/",
}

// List returns a filtered, paginated slice along with the total matching count.
func (s *Store) List(f RequestFilter) ([]*CapturedRequest, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build extensions set if provided.
	var extSet map[string]struct{}
	includeMode := strings.EqualFold(f.ExtMode, "include")
	if f.Exclude != "" {
		parts := strings.Split(f.Exclude, ",")
		extSet = make(map[string]struct{}, len(parts))
		for _, p := range parts {
			ext := strings.TrimSpace(p)
			if ext != "" {
				extSet[strings.ToLower(ext)] = struct{}{}
			}
		}
	}

	// Resolve content type keywords (comma-separated) to MIME substrings.
	var ctMatches []string
	if f.ContentType != "" {
		for _, raw := range strings.Split(f.ContentType, ",") {
			kw := strings.ToLower(strings.TrimSpace(raw))
			if kw == "" {
				continue
			}
			if mapped, ok := contentTypeKeywords[kw]; ok {
				ctMatches = append(ctMatches, mapped)
			} else {
				ctMatches = append(ctMatches, kw)
			}
		}
	}

	// Prepare content matching (searches raw request + response bytes).
	// Include mode keeps matching requests; exclude mode drops them.
	contentExclude := strings.EqualFold(f.ContentMode, "exclude")
	var contentRe *regexp.Regexp
	var contentNeedle string
	contentActive := f.Content != ""
	if contentActive {
		if f.ContentRegex {
			// An invalid pattern matches nothing (regex stays nil).
			contentRe, _ = regexp.Compile(f.Content)
		} else {
			contentNeedle = strings.ToLower(f.Content)
		}
	}

	var filtered []*CapturedRequest
	for _, r := range s.items {
		if f.Host != "" && r.Host != f.Host {
			continue
		}
		if f.Method != "" && !strings.EqualFold(r.Method, f.Method) {
			continue
		}
		if f.Status != 0 && r.StatusCode != f.Status {
			continue
		}
		if f.Search != "" && !strings.Contains(strings.ToLower(r.URL), strings.ToLower(f.Search)) {
			continue
		}
		if len(extSet) > 0 {
			if u, err := url.Parse(r.URL); err == nil {
				ext := strings.ToLower(path.Ext(u.Path))
				_, found := extSet[ext]
				if includeMode && !found {
					continue
				}
				if !includeMode && found {
					continue
				}
			} else if includeMode {
				continue
			}
		}
		if len(ctMatches) > 0 {
			ct := strings.ToLower(r.ContentType)
			matched := false
			for _, m := range ctMatches {
				if strings.Contains(ct, m) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if contentActive {
			var matched bool
			if f.ContentRegex {
				matched = contentRe != nil && (contentRe.Match(r.ReqRaw) || contentRe.Match(r.RespRaw))
			} else {
				matched = strings.Contains(strings.ToLower(string(r.ReqRaw)), contentNeedle) ||
					strings.Contains(strings.ToLower(string(r.RespRaw)), contentNeedle)
			}
			if contentExclude {
				if matched {
					continue
				}
			} else if !matched {
				continue
			}
		}
		if f.InScopeFunc != nil {
			reqPath := "/"
			if u, err := url.Parse(r.URL); err == nil {
				reqPath = u.Path
			}
			if !f.InScopeFunc(r.Host, r.Method, reqPath) {
				continue
			}
		}
		filtered = append(filtered, r)
	}

	total := len(filtered)
	if f.Offset >= total {
		return []*CapturedRequest{}, total
	}

	end := f.Offset + f.Limit
	if f.Limit <= 0 || end > total {
		end = total
	}

	return filtered[f.Offset:end], total
}

// Hosts returns a sorted, deduplicated list of hosts from the ring buffer.
func (s *Store) Hosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	for _, r := range s.items {
		if r.Host != "" {
			seen[r.Host] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// All returns a copy of all stored requests.
func (s *Store) All() []*CapturedRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*CapturedRequest, len(s.items))
	copy(out, s.items)
	return out
}

// LoadItems replaces all stored requests with the given items.
// If more items are provided than maxSize, only the last maxSize are kept.
func (s *Store) LoadItems(items []*CapturedRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = s.items[:0]
	s.nextSeq = 0
	start := 0
	if len(items) > s.maxSize {
		start = len(items) - s.maxSize
	}
	for _, r := range items[start:] {
		s.items = append(s.items, r)
		if r.Seq > s.nextSeq {
			s.nextSeq = r.Seq
		}
	}
}

// MaxSize returns the current ring buffer capacity.
func (s *Store) MaxSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxSize
}

// SetMaxSize updates the ring buffer capacity. If the current number of items
// exceeds the new capacity, the oldest items are trimmed.
func (s *Store) SetMaxSize(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxSize = n
	if len(s.items) > n {
		s.items = s.items[len(s.items)-n:]
	}
}

// SitemapVariant represents a unique query-parameter-name combination
// observed for an endpoint, along with the ID of the latest matching request.
type SitemapVariant struct {
	Params    []string `json:"params"`
	RequestID string   `json:"requestId"`
	Count     int      `json:"count"`
}

// SitemapEndpoint represents a unique path within a host.
type SitemapEndpoint struct {
	Path     string           `json:"path"`
	Methods  []string         `json:"methods"`
	Params   []string         `json:"params"`
	Variants []SitemapVariant `json:"variants"`
	Count    int              `json:"count"`
}

// SitemapHost represents a unique origin (scheme://host:port).
type SitemapHost struct {
	Origin    string            `json:"origin"`
	Endpoints []SitemapEndpoint `json:"endpoints"`
	Count     int               `json:"count"`
}

// Sitemap builds an aggregated site map from all captured requests.
// Hosts are keyed by origin (scheme://host:port). Within each host,
// endpoints are grouped by path with observed methods and query param names.
func (s *Store) Sitemap() []SitemapHost {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type endpointKey struct {
		origin string
		path   string
	}

	type variantData struct {
		paramNames []string
		requestID  string
		count      int
	}

	type endpointData struct {
		methods  map[string]struct{}
		params   map[string]struct{}
		variants map[string]*variantData // keyed by joined sorted param names
		count    int
	}

	hostCounts := make(map[string]int)
	endpoints := make(map[endpointKey]*endpointData)
	hostOrder := make(map[string]struct{})

	for _, r := range s.items {
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		hostCounts[origin]++
		hostOrder[origin] = struct{}{}

		key := endpointKey{origin: origin, path: u.Path}
		ep, ok := endpoints[key]
		if !ok {
			ep = &endpointData{
				methods:  make(map[string]struct{}),
				params:   make(map[string]struct{}),
				variants: make(map[string]*variantData),
			}
			endpoints[key] = ep
		}
		ep.count++
		ep.methods[r.Method] = struct{}{}

		// Collect sorted param names for this request.
		qp := u.Query()
		paramNames := make([]string, 0, len(qp))
		for param := range qp {
			ep.params[param] = struct{}{}
			paramNames = append(paramNames, param)
		}
		sort.Strings(paramNames)
		variantKey := strings.Join(paramNames, ",")

		v, ok := ep.variants[variantKey]
		if !ok {
			v = &variantData{paramNames: paramNames}
			ep.variants[variantKey] = v
		}
		v.count++
		v.requestID = r.ID // latest wins
	}

	// Collect and sort hosts.
	hosts := make([]SitemapHost, 0, len(hostOrder))
	for origin := range hostOrder {
		hosts = append(hosts, SitemapHost{
			Origin: origin,
			Count:  hostCounts[origin],
		})
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].Origin < hosts[j].Origin
	})

	// Attach endpoints to each host.
	for i := range hosts {
		origin := hosts[i].Origin
		var eps []SitemapEndpoint
		for key, data := range endpoints {
			if key.origin != origin {
				continue
			}
			methods := make([]string, 0, len(data.methods))
			for m := range data.methods {
				methods = append(methods, m)
			}
			sort.Strings(methods)

			params := make([]string, 0, len(data.params))
			for p := range data.params {
				params = append(params, p)
			}
			sort.Strings(params)

			// Build sorted variants list.
			variants := make([]SitemapVariant, 0, len(data.variants))
			for _, vd := range data.variants {
				variants = append(variants, SitemapVariant{
					Params:    vd.paramNames,
					RequestID: vd.requestID,
					Count:     vd.count,
				})
			}
			sort.Slice(variants, func(a, b int) bool {
				return strings.Join(variants[a].Params, ",") < strings.Join(variants[b].Params, ",")
			})

			eps = append(eps, SitemapEndpoint{
				Path:     key.path,
				Methods:  methods,
				Params:   params,
				Variants: variants,
				Count:    data.count,
			})
		}
		sort.Slice(eps, func(a, b int) bool {
			return eps[a].Path < eps[b].Path
		})
		hosts[i].Endpoints = eps
	}

	return hosts
}

// Clear removes all stored requests.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = s.items[:0]
	s.nextSeq = 0
}
