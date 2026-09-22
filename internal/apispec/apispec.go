// Package apispec parses API description documents into one normalized model and
// projects that model into raw HTTP requests.
//
// The parsing and placeholder-value approach is ported from BishopFox's sj
// (github.com/BishopFox/sj), which audits exposed Swagger/OpenAPI documents by
// building a request for every declared operation. See the notes on individual
// functions for the places this deliberately diverges.
//
// # The spec is the editing document; the raw request is the executable truth
//
// Nothing here sends. Render takes no context.Context and this package imports
// nothing that can open a socket, so that is structural rather than a
// convention. Render turns one operation plus a set of values into the exact
// bytes that go on the wire, and those bytes are what the operator sees, edits,
// and hands to the senders that already exist.
//
// The consequence is the point: because a spec-driven request is just bytes,
// scope, Match & Replace, Custom Data and intercept all apply to it without this
// package knowing they exist, and a spec-driven request can be handed to the
// request workbench or the fuzzer with nothing lost in translation. A send path
// private to the spec tab is what would break it.
//
// # A $ref never reaches the filesystem
//
// sj resolves external file references ("./schemas/user.yaml#/User") off local
// disk. There, the document is a file the operator chose. Here, a document is
// routinely fetched from a target and is therefore attacker-controlled, and
// following a file reference would not merely be arbitrary file read: the value
// read is rendered into a request body and sent to a host the same document
// chose, which makes it exfiltration. Local "#/..." pointers only. Everything
// else is refused and reported as a Diagnostic.
//
// # A document always parses to something
//
// Parse errors are reserved for input that is not a document at all. Everything
// survivable — a refused reference, a dangling pointer, a cycle, an exhausted
// budget, a duplicate key — degrades that one schema and appends a Diagnostic.
// An operator reading a 400 from a generated request needs to know the body came
// from a schema that could not be fully resolved; the alternative is assuming the
// endpoint rejects valid input.
package apispec

// Format identifies the kind of document a Spec was parsed from. The normalized
// model is deliberately free of OpenAPI vocabulary so that a parser for another
// description language is a sibling file returning the same *Spec.
type Format string

const (
	FormatSwagger2 Format = "swagger2"
	FormatOpenAPI3 Format = "openapi3"
)

// Limits bound what a hostile or merely enormous document can cost. They are
// fields rather than constants only where a caller has a legitimate reason to
// differ; the defaults are what DefaultOptions supplies.
const (
	// MaxSpecBytes is checked against the raw bytes before any decode. Sized
	// against real documents rather than a round number: GitHub's is 13 MB and
	// Stripe's 3.7 MB, so 8 MB refused the two largest public APIs outright.
	// MaxDocNodes is the real memory backstop; this only bounds the read.
	MaxSpecBytes = 24 << 20

	// MaxDocNodes bounds the decoded document. yaml.v3 has its own alias-ratio
	// guard against billion-laughs (see decodeDocument), but that is a ratio and
	// not a memory cap, so a large document can pass it and still expand.
	MaxDocNodes = 2_000_000

	// MaxRefDepth and MaxSchemaNodes bound schema expansion. A cycle is caught by
	// the reference stack; these catch allOf/oneOf nesting that blows up
	// combinatorially with no cycle anywhere.
	MaxRefDepth    = 32
	MaxSchemaNodes = 50_000

	// MaxPointerSegments bounds one JSON pointer.
	MaxPointerSegments = 64

	// MaxOperations bounds one document's operation count. Reaching it is
	// reported as a Diagnostic rather than silently truncating.
	MaxOperations = 2000
)

// Spec is a parsed API description, normalized away from its source format.
// Everything an operator can edit or send lives here; nothing here knows how the
// document was written.
type Spec struct {
	ID          string `json:"id"`
	Format      Format `json:"format"`
	Version     string `json:"version"` // the document's own token: "2.0", "3.0.1"
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`

	Servers    []Server    `json:"servers"`
	Operations []Operation `json:"operations"`

	// Auth is what the document says exists. It never holds a secret: a
	// credential is supplied per render, as an Auth value.
	Auth     []AuthScheme          `json:"auth"`
	Security []SecurityRequirement `json:"security,omitempty"`

	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`

	SourceURL string `json:"sourceUrl,omitempty"`
	SizeBytes int    `json:"sizeBytes"`

	// Placeholders are the effective values, after withDefaults, that generated
	// every Param.Default and every body in this Spec.
	//
	// Recorded rather than left implicit because the UI shows a generated value
	// as an input hint. A Spec that did not state its own generation inputs would
	// let that hint and the bytes on the wire disagree with nothing to compare
	// them against — the failure this package's "bytes are truth" rule exists to
	// prevent. It is also what lets two views of one document agree that they are
	// looking at the same parse.
	Placeholders Placeholders `json:"placeholders"`
}

// normalize materializes every collection a client iterates unconditionally.
//
// # A nil slice and an empty slice are the same value in Go and different values on the wire
//
// encoding/json writes a nil slice as null, not []. So every collection crossing
// the API boundary has to be one of exactly two things:
//
//   - omitempty, so an empty one is *absent* and the client's field is optional; or
//   - guaranteed non-nil here, so it is [] and the client's field is a plain array.
//
// A field that is both non-omitempty and nillable is the combination that ships
// null against a type promising an array, and it is invisible to both compilers:
// Go sees a legal nil slice, TypeScript sees a declaration it has no way to
// check. That combination is what crashed the operations view on any document
// with a requestBody-only operation — the commonest shape in OpenAPI 3.
//
// Adding a collection field to Spec or Operation means choosing one of the two,
// and if it is the second, adding it here. The corpus test pins this by
// asserting the marshalled document contains no null for these fields.
func (s *Spec) normalize() {
	if s.Servers == nil {
		s.Servers = []Server{}
	}
	if s.Operations == nil {
		s.Operations = []Operation{}
	}
	if s.Auth == nil {
		s.Auth = []AuthScheme{}
	}
	for i := range s.Operations {
		if s.Operations[i].Params == nil {
			s.Operations[i].Params = []Param{}
		}
	}
}

// Server is one declared origin. A document may name several, or name one
// relative to wherever it was served from; both are reported rather than
// resolved to a single answer, because picking for the operator is how a scan
// ends up pointed at the wrong host.
type Server struct {
	URL         string            `json:"url"` // exactly as written
	Scheme      string            `json:"scheme,omitempty"`
	Host        string            `json:"host,omitempty"` // host[:port]
	BasePath    string            `json:"basePath"`       // "" or "/v1", never trailing "/"
	Description string            `json:"description,omitempty"`
	Vars        map[string]string `json:"vars,omitempty"`
}

// Operation is one method on one path.
type Operation struct {
	ID          string   `json:"id"` // operationId when usable, else "get:/pets/{id}"
	Method      string   `json:"method"`
	Path        string   `json:"path"` // the template, braces intact
	Summary     string   `json:"summary,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Deprecated  bool     `json:"deprecated,omitempty"`

	Params []Param `json:"params"`

	// Bodies holds one entry per declared content type, in document order.
	// Bodies[0] is what Render uses unless Values selects another. sj keeps only
	// the last one a map iteration happened to yield.
	Bodies       []Body `json:"bodies,omitempty"`
	BodyRequired bool   `json:"bodyRequired,omitempty"`

	// Responses is keyed exactly as the document wrote it ("200", "4XX",
	// "default"). String-keyed on purpose: sj builds this with an any key and
	// then looks it up with an int, so the description never resolves.
	Responses map[string]string `json:"responses,omitempty"`

	// Security nil means "inherit Spec.Security". A non-nil empty slice means the
	// operation explicitly opts out of authentication, which is a meaningful
	// statement and not the same thing.
	//
	// No omitempty, deliberately: it omits a non-nil empty slice exactly as it
	// omits a nil one, which would erase on the wire the very distinction the
	// lines above take care to build.
	Security []SecurityRequirement `json:"security"`

	// Destructive is advisory, computed by Classify. It never stops a render; it
	// gates a send.
	Destructive        bool     `json:"destructive,omitempty"`
	DestructiveReasons []string `json:"destructiveReasons,omitempty"`

	// Servers is the operation's own server list, from the operation or its path
	// item. Empty means "use the document's". OpenAPI 3 allows the override and
	// multi-service gateways use it.
	Servers []Server `json:"servers,omitempty"`

	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// ParamIn is where a parameter is carried.
type ParamIn string

const (
	InPath   ParamIn = "path"
	InQuery  ParamIn = "query"
	InHeader ParamIn = "header"
	InCookie ParamIn = "cookie"
)

// Param is one input to an operation.
type Param struct {
	Name        string  `json:"name"`
	In          ParamIn `json:"in"`
	Required    bool    `json:"required,omitempty"`
	Deprecated  bool    `json:"deprecated,omitempty"`
	Description string  `json:"description,omitempty"`

	Type   string   `json:"type,omitempty"`
	Format string   `json:"format,omitempty"`
	Enum   []string `json:"enum,omitempty"`

	// Default is the value the parser generated, already in wire form. An
	// operator override arrives through Values and never mutates this, so the UI
	// can keep showing it as the placeholder after the field is cleared.
	Default string `json:"default"`

	// ExplodedFrom names the object-schema parameter this one was split out of.
	// An OpenAPI 3 query parameter whose schema is an object becomes one Param
	// per property, which is the only place the parser invents a name. Render
	// regroups them by this to rebuild the wire form the style calls for.
	ExplodedFrom string `json:"explodedFrom,omitempty"`

	// Style and Explode select the serialization. Render reads both; the pair
	// decides whether an object goes out as "?a=1&b=2", "?o=a,1,b,2" or
	// "?o[a]=1&o[b]=2", which are three different requests.
	Style   string `json:"style,omitempty"`
	Explode bool   `json:"explode,omitempty"`

	// ContentType is set when the document declared the parameter with `content`
	// rather than `schema`, meaning its value is a serialized media type.
	ContentType string `json:"contentType,omitempty"`
}

// BodyEncoding is how a Body's bytes were built, which is what the UI needs to
// choose an editor and what Render needs to leave alone.
type BodyEncoding string

const (
	EncJSON      BodyEncoding = "json"
	EncXML       BodyEncoding = "xml"
	EncForm      BodyEncoding = "form"
	EncMultipart BodyEncoding = "multipart"
	EncRaw       BodyEncoding = "raw"
)

// Body is one request body variant.
type Body struct {
	ContentType string       `json:"contentType"`
	Encoding    BodyEncoding `json:"encoding"`
	Content     []byte       `json:"content"`
	Fields      []string     `json:"fields,omitempty"`

	// Boundary is stored with the bytes it framed. Regenerating one at render
	// time, as sj does, produces a Content-Type that does not describe the body.
	Boundary string `json:"boundary,omitempty"`
}

// AuthKind is a security scheme's type, normalized across v2 and v3 spellings.
type AuthKind string

const (
	AuthBasic     AuthKind = "basic"
	AuthBearer    AuthKind = "bearer"
	AuthAPIKey    AuthKind = "apiKey"
	AuthHTTPOther AuthKind = "http"
	AuthOAuth2    AuthKind = "oauth2"
	AuthOpenID    AuthKind = "openIdConnect"
	AuthMutualTLS AuthKind = "mutualTLS"
)

// AuthScheme is one way the document says a request may authenticate.
//
// Both spellings are read: OpenAPI 3's components.securitySchemes and Swagger
// 2's securityDefinitions. sj reads only the former, so a v2 document gets no
// authentication at all.
type AuthScheme struct {
	Name         string   `json:"name"` // the key under the document's scheme map
	Kind         AuthKind `json:"kind"`
	In           ParamIn  `json:"in,omitempty"`        // apiKey only
	ParamName    string   `json:"paramName,omitempty"` // apiKey only
	Scheme       string   `json:"scheme,omitempty"`    // raw http scheme token
	BearerFormat string   `json:"bearerFormat,omitempty"`
	Description  string   `json:"description,omitempty"`

	// Automatable is false for oauth2, openIdConnect and mutualTLS: Joro cannot
	// obtain those credentials, only carry one the operator supplied.
	Automatable bool `json:"automatable"`
}

// SecurityRequirement is one alternative: every scheme named in it must be
// satisfied. A slice of these is a disjunction.
type SecurityRequirement struct {
	Schemes []string            `json:"schemes"`
	Scopes  map[string][]string `json:"scopes,omitempty"`
}

// DiagKind classifies what could not be done.
type DiagKind string

const (
	DiagExternalRef   DiagKind = "external_ref"   // refused, never fetched
	DiagUnresolvedRef DiagKind = "unresolved_ref" // "#/..." pointing at nothing
	DiagRefCycle      DiagKind = "ref_cycle"
	DiagDepthExceeded DiagKind = "depth_exceeded"
	DiagNodeBudget    DiagKind = "node_budget"
	DiagDuplicateKey  DiagKind = "duplicate_key"
	DiagTruncated     DiagKind = "truncated"
	DiagUnsupported   DiagKind = "unsupported"
	DiagMalformed     DiagKind = "malformed"
)

// Diagnostic is one thing the parser refused or could not complete.
type Diagnostic struct {
	Kind    DiagKind `json:"kind"`
	Ref     string   `json:"ref,omitempty"`     // the offending $ref, member or content type
	Pointer string   `json:"pointer,omitempty"` // where: "/paths/~1pets/get/requestBody"
	Detail  string   `json:"detail,omitempty"`
}

// Values overrides the parser's generated defaults for one render. Keys are
// ValueKey(in, name); the reserved keys "body" and "contentType" carry the whole
// body and the selection among Operation.Bodies. An absent key means "use what
// the parser generated"; a present key with an empty value means "send it empty",
// which is a different and useful test.
type Values map[string]string

// ValueKey builds the Values key for one parameter.
func ValueKey(in ParamIn, name string) string { return string(in) + ":" + name }

// Reserved Values keys.
const (
	ValueKeyBody        = "body"
	ValueKeyContentType = "contentType"
)

// Options tunes a parse.
type Options struct {
	// SourceURL is where the document was served from. It is the base for a
	// relative server URL and is recorded on the Spec; it is never fetched.
	SourceURL string

	// Placeholders supplies the generated values. The zero value is filled in
	// from DefaultPlaceholders.
	//
	// A placeholder is an input to the *parse*, not to a render: it is baked into
	// Param.Default and into body bytes, which no per-request substitution
	// reaches. So changing one means parsing the document again, and the effective
	// values are recorded on the resulting Spec. RenderOptions deliberately has no
	// counterpart — a per-request placeholder would re-decode a multi-megabyte
	// document on every preview, and would move the wire bytes while the UI kept
	// showing the values of the parse it still holds.
	Placeholders Placeholders

	// DestructiveWhitelist names keywords to stop treating as destructive, for a
	// target whose vocabulary collides with the list ("order" on a commerce API
	// that only reads orders).
	DestructiveWhitelist []string
}

// Placeholders are the values generated for a schema that declares no example
// and no enum. The defaults match sj's, so a Joro-generated request and an
// sj-generated request for the same document agree.
type Placeholders struct {
	String string `json:"string"` // sj: --test-string, default "bishopfox"
	Date   string `json:"date"`   // sj: -d, default "1990-01-01"
	URL    string `json:"url"`    // sj: -c, default "https://bishopfox.com"
	Email  string `json:"email"`  // sj: --custom-email
}

// DefaultPlaceholders returns sj's defaults.
func DefaultPlaceholders() Placeholders {
	return Placeholders{
		String: "bishopfox",
		Date:   "1990-01-01",
		URL:    "https://bishopfox.com",
		Email:  "noreply@localhost.localdomain",
	}
}

// withDefaults fills empty fields, so a caller may set only what it cares about.
func (p Placeholders) withDefaults() Placeholders {
	d := DefaultPlaceholders()
	if p.String == "" {
		p.String = d.String
	}
	if p.Date == "" {
		p.Date = d.Date
	}
	if p.URL == "" {
		p.URL = d.URL
	}
	if p.Email == "" {
		p.Email = d.Email
	}
	return p
}
