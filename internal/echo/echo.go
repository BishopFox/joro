// Package echo maps every value a request sent to every place it comes back in
// the response, the transform it came back through, and the syntactic context it
// landed in. It is a triage aid for injection work: "reflected" alone is noise,
// because a busy page reflects dozens of values, so the useful unit is a
// reflection plus what survived it.
//
// The engine decodes the haystack; it never encodes the needle. Searching a
// response for an encoded form of a value means guessing which characters the
// application encoded and in which hex case, and it misses the common case
// outright — an application that escapes only < > & " and leaves the rest is
// never matched by a wholesale-encoded needle. Decoding the response into a
// handful of views and searching those for the literal value has neither
// problem. internal/chain/bind.go states the same rule for the same reason and
// declines to act on it, because a chain binding has nowhere to put a transform.
//
// The inversion is also what makes the cost bearable. Encoding needles costs
// values x transforms passes over the body; decoding views costs views passes,
// so the number of parameters a request carried stops multiplying the work. The
// views a body cannot contain are skipped on a single byte scan, which leaves
// the common response at two passes rather than a dozen.
//
// Analysis is per message: a value sent in a request is searched for in that
// request's own response. Values crossing messages — a name stored on one page
// and rendered on another — are a different question with a different cost, and
// are not answered here.
//
// Owning the walk means owning both halves of the question. inventory.go answers
// what a request sent, with no response involved, because the walker that already
// enumerates every input is here and a second one would drift from it. That half
// is built on demand for one site-map node and holds no state: it is the only
// part of the package that says anything when the engine has never been switched
// on, which is the point — an operator inventorying an endpoint's inputs has not
// asked about reflection yet.
//
// Only a reflection that can leave its context mints a detect.Finding, through
// detect.FindingID and detect.Store.Upsert, the path internal/anomaly and
// internal/capreg also use. Everything else stays in this package's own store,
// which is session state: a report holds no triage of its own and a rescan
// rebuilds it from history.
package echo

import "time"

// Source names where in the request a value was found.
type Source string

const (
	SourceQuery     Source = "query"
	SourcePath      Source = "path"
	SourceForm      Source = "form"
	SourceJSON      Source = "json"
	SourceMultipart Source = "multipart"
	SourceHeader    Source = "header"
	SourceCookie    Source = "cookie"
)

// Sources lists every source in display order.
var Sources = []Source{
	SourceQuery, SourcePath, SourceForm, SourceJSON,
	SourceMultipart, SourceHeader, SourceCookie,
}

// Transform names how a value was re-encoded on its way into the response. A
// composed transform joins its steps with "+", outermost first, so the name
// reads in the order a decoder strips them.
type Transform string

const (
	TransformIdentity     Transform = "identity"
	TransformPercent      Transform = "percent"
	TransformHTMLEntity   Transform = "html_entity"
	TransformJSString     Transform = "js_string"
	TransformBase64       Transform = "base64"
	TransformPercentHTML  Transform = "percent+html_entity"
	TransformPercentTwice Transform = "percent+percent"
	TransformHTMLPercent  Transform = "html_entity+percent"
)

// Context names the syntactic position a reflection landed in. The classifier
// answers what a browser would do with those bytes, not what the specification
// says they mean.
type Context string

const (
	ContextHTMLText    Context = "html_text"
	ContextHTMLComment Context = "html_comment"
	ContextTagName     Context = "tag_name"
	ContextAttrName    Context = "attr_name"
	ContextAttrValue   Context = "attr_value"
	ContextScript      Context = "script"
	ContextStyle       Context = "style"
	ContextJSONString  Context = "json_string"
	ContextJSONKey     Context = "json_key"
	ContextHeaderValue Context = "header_value"
	ContextPlain       Context = "plain"
)

// Contexts lists every context in display order.
var Contexts = []Context{
	ContextHTMLText, ContextAttrValue, ContextAttrName, ContextTagName,
	ContextScript, ContextStyle, ContextHTMLComment,
	ContextJSONString, ContextJSONKey, ContextHeaderValue, ContextPlain,
}

// JSContext sub-classifies a reflection inside a script block. Whether a value
// sits in code or inside a string literal decides what it takes to escape.
type JSContext string

const (
	JSCode          JSContext = "code"
	JSStringSingle  JSContext = "string_single"
	JSStringDouble  JSContext = "string_double"
	JSTemplate      JSContext = "template"
	JSComment       JSContext = "comment"
	JSRegexpLiteral JSContext = "regexp"
)

// Confidence rates how likely a match is a real reflection rather than a
// coincidence. Short, low-entropy and date- or counter-shaped values collide
// with page text on their own.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Span is a half-open byte range. Its coordinate system is whatever the
// enclosing struct names; a span is meaningless without one.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Value is one input located in the request document.
type Value struct {
	Source Source `json:"source"`
	// Name is the parameter name, or a dotted path with [i] indices for a value
	// reached by walking a JSON body.
	Name string `json:"name"`
	// Value is the decoded form — the bytes actually searched for.
	Value string `json:"value"`
	// Span locates the value inside the raw request document. Zero when the
	// value has no contiguous run of its own there, which a decoded form does
	// not always have.
	Span Span `json:"span"`
}

// Key identifies the parameter a value came from, independent of the value.
func (v Value) Key() string { return string(v.Source) + ":" + v.Name }

// Reflection is one occurrence of a sent value in the response.
type Reflection struct {
	Source Source `json:"source"`
	Name   string `json:"name"`
	Value  string `json:"value"`

	Transform Transform `json:"transform"`
	Context   Context   `json:"context"`
	JSContext JSContext `json:"jsContext,omitempty"`
	// Attr and Quote describe an attribute-value context: the attribute's name
	// and the quote character enclosing it, empty for an unquoted value.
	Attr  string `json:"attr,omitempty"`
	Quote string `json:"quote,omitempty"`

	// Part names the document, and Coord the coordinate system Span indexes.
	// A compressed body is reported against the decoded body, because the raw
	// document shares no coordinates with it and dropping the offset would lose
	// the most common response there is.
	Part  string `json:"part"`
	Coord string `json:"coord"`
	Span  Span   `json:"span"`

	// Survived lists the value's own metacharacters that reached the response
	// literally, in a stable order. Empty means the sink neutralized all of them.
	Survived string `json:"survived,omitempty"`
	// Breakout reports that Survived is enough to leave Context.
	Breakout   bool       `json:"breakout"`
	Confidence Confidence `json:"confidence"`
}

// SinkKey identifies a distinct place a parameter lands, for the roll-up.
func (r Reflection) SinkKey() string {
	return string(r.Context) + "|" + string(r.Transform) + "|" + string(r.JSContext)
}

// Report is the analysis of one captured message.
type Report struct {
	RequestID string    `json:"requestId"`
	Seq       int       `json:"seq"`
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`

	// Values counts the candidate inputs considered, which is larger than the
	// needle set: values below the admission bar are counted and not searched.
	Values    int `json:"values"`
	Needles   int `json:"needles"`
	Breakouts int `json:"breakouts"`

	Reflections []Reflection `json:"reflections"`

	// Truncated marks that a cap was hit, so the report cannot claim to be
	// exhaustive.
	Truncated bool `json:"truncated"`
}

// Config tunes the engine. Read fresh each cycle so a change takes effect
// without a restart.
type Config struct {
	Enabled   bool `json:"enabled"`
	ScopeOnly bool `json:"scopeOnly"`

	// MaxBodyScanBytes is deliberately below detect's equivalent: this engine
	// makes several linear passes over a body where a rule makes one.
	MaxBodyScanBytes        int `json:"maxBodyScanBytes"`
	MaxRequestBodyScanBytes int `json:"maxRequestBodyScanBytes"`

	MinValueLen              int `json:"minValueLen"`
	MaxValuesPerRequest      int `json:"maxValuesPerRequest"`
	MaxReflectionsPerRequest int `json:"maxReflectionsPerRequest"`

	// TransformDepth 2 admits the composed views. Depth is capped rather than
	// open because each extra level multiplies the view count and the yield
	// falls off a cliff after two.
	TransformDepth int  `json:"transformDepth"`
	Base64         bool `json:"base64"`

	// ScanHeaders admits request headers and cookies as sources. Off by default:
	// a session cookie echoed into a page is normal and drowns the map.
	ScanHeaders bool `json:"scanHeaders"`

	ExcludeHosts []string `json:"excludeHosts,omitempty"`
}

// DefaultConfig returns the configuration the engine starts with.
func DefaultConfig() Config {
	return Config{
		Enabled:                  false,
		ScopeOnly:                true,
		MaxBodyScanBytes:         512 << 10,
		MaxRequestBodyScanBytes:  256 << 10,
		MinValueLen:              6,
		MaxValuesPerRequest:      512,
		MaxReflectionsPerRequest: 200,
		TransformDepth:           2,
		Base64:                   true,
		ScanHeaders:              false,
	}
}

// Normalize clamps a configuration that arrived from an API patch or a
// hand-edited project file into the range the engine can honor.
func (c *Config) Normalize() {
	d := DefaultConfig()
	if c.MaxBodyScanBytes <= 0 {
		c.MaxBodyScanBytes = d.MaxBodyScanBytes
	}
	if c.MaxBodyScanBytes > 8<<20 {
		c.MaxBodyScanBytes = 8 << 20
	}
	if c.MaxRequestBodyScanBytes <= 0 {
		c.MaxRequestBodyScanBytes = d.MaxRequestBodyScanBytes
	}
	if c.MaxRequestBodyScanBytes > 8<<20 {
		c.MaxRequestBodyScanBytes = 8 << 20
	}
	if c.MinValueLen < 3 {
		c.MinValueLen = 3
	}
	if c.MinValueLen > 64 {
		c.MinValueLen = 64
	}
	if c.MaxValuesPerRequest <= 0 {
		c.MaxValuesPerRequest = d.MaxValuesPerRequest
	}
	if c.MaxValuesPerRequest > 5000 {
		c.MaxValuesPerRequest = 5000
	}
	if c.MaxReflectionsPerRequest <= 0 {
		c.MaxReflectionsPerRequest = d.MaxReflectionsPerRequest
	}
	if c.MaxReflectionsPerRequest > 5000 {
		c.MaxReflectionsPerRequest = 5000
	}
	if c.TransformDepth < 1 {
		c.TransformDepth = 1
	}
	if c.TransformDepth > 2 {
		c.TransformDepth = 2
	}
}
