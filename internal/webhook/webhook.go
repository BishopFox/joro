// Package webhook delivers Joro's own events to an endpoint the operator configured.
//
// A webhook adds exactly one idea — a delivery target — and borrows the rest. internal/trigger
// already answers *when*: a webhook names trigger references the same way an automation does,
// and the same Store -> Resolve -> Compile -> Subject -> Matches path decides whether an event
// is worth a delivery. What is new here is where the bytes go, and the two rules below are what
// make that safe to hand to something other than the operator.
//
// # The destination is fixed before any wire byte
//
// This is internal/localcmd's argv rule in a second setting. A capability names a webhook by
// *id*; the URL, the headers and the secrets are never a capability argument, never a
// capability result, and never in an MCP tool schema. An agent chooses among endpoints the
// operator already created and cannot create, edit, or resolve one — there is no create or
// edit capability, which is the whole of that guarantee, since "webhook." is not a reserved
// prefix in internal/capability and nothing else would refuse one. AllowAutomations is the
// second half: a webhook is invocable from a run only because the operator ticked it, which
// is the same shape as an operator arming a command automation.
//
// # The body's shape is fixed before any event value
//
// A custom body is authored as a JSON *document*, parsed at save time, and rendered by walking
// the decoded structure and substituting only inside string leaves, then re-marshalling. Keys,
// nesting, types and array lengths therefore cannot be moved by a target-controlled host header
// or finding name, and escaping is total because encoding/json does it rather than a quoting
// rule written here. See template.go, which is where the walk lives.
//
// # Delivery does not go through Joro's proxy
//
// httptools.SendViaProxy would capture the webhook URL and payload into History, scan Joro's
// own outbound secret with the detect engine, let Match & Replace rewrite it, and let an
// enabled intercept stall it in the operator's queue. A direct client avoids all four — and it
// is also why a webhook watching request.captured cannot feed itself, since its own deliveries
// never become captures.
package webhook

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Bounds on one webhook. Small for the same reason internal/trigger's are: matching runs on
// the goroutine draining Joro's event bus, and these multiply with the number of enabled
// webhooks.
const (
	MaxIDLen       = 64
	MaxNameLen     = 80
	MaxDescLen     = 400
	MaxURLLen      = 2048
	MaxHeaders     = 20
	MaxHeaderLen   = 1024
	MaxSecretLen   = 512
	MaxTemplateLen = 16 << 10

	// MaxBodyBytes caps a rendered body. Past it the delivery is refused rather than
	// truncated: half a JSON document is not a smaller notification, it is a broken one.
	MaxBodyBytes = 256 << 10

	// MaxValueLen caps one substituted value. A finding name or a URL is far under it; the
	// cap exists so a field that turns out to be long cannot be the whole body.
	MaxValueLen = 4 << 10

	// MaxTriggerRefs bounds how many triggers one webhook watches.
	MaxTriggerRefs = 8
)

// Delivery policy bounds. Defaults are what a webhook gets when it names none.
const (
	DefaultTimeoutMs     = 10_000
	MaxTimeoutMs         = 60_000
	DefaultRetries       = 2
	MaxRetries           = 5
	DefaultMinIntervalMs = 1_000
	MaxMinIntervalMs     = 3_600_000

	// MaxBatch bounds how many events one batched delivery carries.
	MaxBatch = 50
)

// Body formats.
//
// The three presets exist because they are the shapes an operator would otherwise have to
// look up, and getting one wrong produces a 400 from a service rather than an error from
// Joro. FormatTemplate is the escape hatch and the only one that reads the Template field.
const (
	FormatEnvelope = "envelope"
	FormatSlack    = "slack"
	FormatDiscord  = "discord"
	FormatTemplate = "template"
)

// Formats lists every body format, in the order the editor offers them.
var Formats = []string{FormatEnvelope, FormatSlack, FormatDiscord, FormatTemplate}

// Delivery modes: one request per event, or one carrying the batch.
//
// A template renders one event's fields, so it implies DeliveryEach and Validate says so
// rather than silently rendering the first of fifty.
const (
	DeliveryEach  = "each"
	DeliveryBatch = "batch"
)

// Deliveries lists every delivery mode.
var Deliveries = []string{DeliveryEach, DeliveryBatch}

// Authentication kinds.
const (
	AuthNone   = "none"
	AuthBearer = "bearer"
	AuthBasic  = "basic"
	AuthHeader = "header"
)

// AuthKinds lists every authentication kind, in the order the editor offers them.
var AuthKinds = []string{AuthNone, AuthBearer, AuthBasic, AuthHeader}

// Methods lists the request methods a webhook may use. Only the three that carry a body:
// a webhook with nothing to say is not a webhook.
var Methods = []string{"POST", "PUT", "PATCH"}

// The headers every delivery carries, so a receiver can route and de-duplicate without
// parsing the body. Named after the convention the services this talks to already use.
const (
	HeaderEvent     = "X-Joro-Event"
	HeaderTrigger   = "X-Joro-Trigger"
	HeaderDelivery  = "X-Joro-Delivery"
	HeaderTimestamp = "X-Joro-Timestamp"

	// DefaultSignatureHeader carries the HMAC when signing is on. Configurable because a
	// receiver written for another producer may already look somewhere else.
	DefaultSignatureHeader = "X-Joro-Signature"
)

// idPattern is the automation and trigger id pattern, reused so an operator learns one rule
// for every named object in Joro.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// headerNamePattern is RFC 7230's token production. Enforced because a header name is the
// one operator-supplied string that goes onto the wire unescaped.
var headerNamePattern = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+._` + "`" + `|~^-]+$`)

// Header is one custom header. Value is a secret as often as not — an API key, a channel
// token — so it lives under the same 0600 file and the same write-only API rule as Auth.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Auth is how a delivery authenticates.
//
// A separate field rather than "write it yourself in Headers", because the editor can then
// label the secret and the API can withhold it. AuthHeader is the general case and exists so
// a service with its own scheme does not need a code change.
type Auth struct {
	Kind string `json:"kind"`

	// Token is the bearer token, the AuthHeader value, or the basic password.
	Token string `json:"token,omitempty"`

	// User is the basic username. Not a secret on its own, so it is returned by the API
	// where Token is not.
	User string `json:"user,omitempty"`

	// Header names the header for AuthHeader.
	Header string `json:"header,omitempty"`
}

// Signing is HMAC-SHA256 over the timestamp and the body, so a receiver can prove a delivery
// came from this Joro and is not a replay.
//
// The signed string is "<unix seconds>.<body>" rather than the body alone, which is what makes
// the timestamp header meaningful: a receiver that checks only the body signature will accept
// a captured delivery forever.
type Signing struct {
	Enabled bool   `json:"enabled"`
	Secret  string `json:"secret,omitempty"`
	Header  string `json:"header,omitempty"`
}

// Webhook is one configured endpoint.
type Webhook struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// Enabled is the operator's switch. Paused is Joro's: the breaker sets it when a webhook
	// exceeds its rate, and it is separate so resuming restores what the operator wanted
	// rather than asking them to remember it. Both persist.
	Enabled      bool   `json:"enabled"`
	Paused       bool   `json:"paused,omitempty"`
	PausedReason string `json:"pausedReason,omitempty"`

	// Triggers are references, resolved exactly as an automation's are: a built-in event
	// name, or a custom trigger id. An unresolvable reference never fires and never means
	// "no filter" — see dispatch.go.
	Triggers []string `json:"triggers"`

	URL     string   `json:"url"`
	Method  string   `json:"method"`
	Headers []Header `json:"headers,omitempty"`
	Auth    Auth     `json:"auth"`
	Signing Signing  `json:"signing"`

	Format   string `json:"format"`
	Template string `json:"template,omitempty"`
	Delivery string `json:"delivery"`

	// Retries is how many times a failed delivery is repeated, and zero means none. It is
	// the one field here where zero is a choice rather than an omission, which is why
	// Normalize does not fill it the way it fills the two around it — a zero timeout or a
	// zero interval means nothing, so those take the default. DefaultRetries is what the
	// editor seeds a new webhook with instead.
	TimeoutMs     int `json:"timeoutMs,omitempty"`
	Retries       int `json:"retries,omitempty"`
	MinIntervalMs int `json:"minIntervalMs,omitempty"`

	// InsecureTLS skips certificate verification for this one endpoint.
	//
	// Off by default and deliberately per-webhook rather than global: a webhook URL is
	// frequently the credential itself, so posting one over an unverified connection is a
	// real downgrade. It exists for an internal receiver with a self-signed cert, which is
	// the case that would otherwise push an operator to a worse workaround.
	InsecureTLS bool `json:"insecureTls,omitempty"`

	// AllowAutomations lets a sandboxed run fire this webhook by id. Off by default; see the
	// package doc.
	AllowAutomations bool `json:"allowAutomations,omitempty"`

	// Problem is computed on the way out and never persisted, the same way a trigger's is:
	// it carries why a stored webhook will not deliver, because the operator's only other
	// signal would be notifications that quietly stopped.
	Problem string `json:"problem,omitempty"`
}

// Normalize trims and fills defaults. Called before Validate so a webhook that omits an
// optional field is accepted rather than corrected by the operator.
func (w *Webhook) Normalize() {
	w.ID = strings.ToLower(strings.TrimSpace(w.ID))
	w.Name = strings.TrimSpace(w.Name)
	w.Description = strings.TrimSpace(w.Description)
	w.URL = strings.TrimSpace(w.URL)
	w.Template = strings.TrimSpace(w.Template)

	if w.Name == "" {
		w.Name = w.ID
	}

	w.Method = strings.ToUpper(strings.TrimSpace(w.Method))
	if w.Method == "" {
		w.Method = "POST"
	}
	w.Format = strings.ToLower(strings.TrimSpace(w.Format))
	if w.Format == "" {
		w.Format = FormatEnvelope
	}
	w.Delivery = strings.ToLower(strings.TrimSpace(w.Delivery))
	if w.Delivery == "" {
		w.Delivery = DeliveryEach
	}

	w.Auth.Kind = strings.ToLower(strings.TrimSpace(w.Auth.Kind))
	if w.Auth.Kind == "" {
		w.Auth.Kind = AuthNone
	}
	w.Auth.Header = strings.TrimSpace(w.Auth.Header)
	w.Auth.User = strings.TrimSpace(w.Auth.User)

	w.Signing.Header = strings.TrimSpace(w.Signing.Header)
	if w.Signing.Header == "" {
		w.Signing.Header = DefaultSignatureHeader
	}

	if w.TimeoutMs <= 0 {
		w.TimeoutMs = DefaultTimeoutMs
	}
	if w.Retries < 0 {
		w.Retries = DefaultRetries
	}
	if w.MinIntervalMs <= 0 {
		w.MinIntervalMs = DefaultMinIntervalMs
	}

	out := make([]string, 0, len(w.Triggers))
	for _, ref := range w.Triggers {
		ref = strings.TrimSpace(ref)
		if ref != "" && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	w.Triggers = out

	for i := range w.Headers {
		w.Headers[i].Name = strings.TrimSpace(w.Headers[i].Name)
	}
}

// Validate reports why a webhook cannot be stored.
//
// This is the write path only, and the asymmetry with Compile is the same one internal/trigger
// documents: reject what you can explain to someone who is standing there, refuse to act on
// what you cannot. A webhook already on disk that fails here still loads and still lists, with
// Problem saying why it will not deliver.
func (w *Webhook) Validate() error {
	switch {
	case w.ID == "":
		return fmt.Errorf("id is required")
	case len(w.ID) > MaxIDLen:
		return fmt.Errorf("id is %d characters, over the %d limit", len(w.ID), MaxIDLen)
	case !idPattern.MatchString(w.ID):
		return fmt.Errorf("id %q is invalid: use lowercase letters, digits, hyphen and "+
			"underscore, starting with a letter or digit", w.ID)
	case len(w.Name) > MaxNameLen:
		return fmt.Errorf("name is %d characters, over the %d limit", len(w.Name), MaxNameLen)
	case len(w.Description) > MaxDescLen:
		return fmt.Errorf("description is %d characters, over the %d limit",
			len(w.Description), MaxDescLen)
	// A webhook needs a reason to fire, and there are two of them. Naming no trigger is
	// valid when automations may fire it: that is a channel a script speaks on, and
	// requiring a trigger it would never use would be a switch that does nothing.
	case len(w.Triggers) == 0 && !w.AllowAutomations:
		return fmt.Errorf("choose at least one trigger, or let automations fire this — " +
			"otherwise it has no reason to fire")
	case len(w.Triggers) > MaxTriggerRefs:
		return fmt.Errorf("this webhook names %d triggers, over the %d limit",
			len(w.Triggers), MaxTriggerRefs)
	case !slices.Contains(Methods, w.Method):
		return fmt.Errorf("method %q is not one of %s", w.Method, strings.Join(Methods, ", "))
	case !slices.Contains(Formats, w.Format):
		return fmt.Errorf("format %q is not one of %s", w.Format, strings.Join(Formats, ", "))
	case !slices.Contains(Deliveries, w.Delivery):
		return fmt.Errorf("delivery %q is not one of %s", w.Delivery, strings.Join(Deliveries, ", "))
	case w.Format == FormatTemplate && w.Delivery != DeliveryEach:
		return fmt.Errorf("a template renders one event's fields, so it needs delivery %q",
			DeliveryEach)
	case w.TimeoutMs > MaxTimeoutMs:
		return fmt.Errorf("timeout is %dms, over the %dms limit", w.TimeoutMs, MaxTimeoutMs)
	case w.Retries > MaxRetries:
		return fmt.Errorf("retries is %d, over the %d limit", w.Retries, MaxRetries)
	case w.MinIntervalMs > MaxMinIntervalMs:
		return fmt.Errorf("minimum interval is %dms, over the %dms limit",
			w.MinIntervalMs, MaxMinIntervalMs)
	}

	if err := w.validateURL(); err != nil {
		return err
	}
	if err := w.validateHeaders(); err != nil {
		return err
	}
	if err := w.validateAuth(); err != nil {
		return err
	}
	if err := w.validateSigning(); err != nil {
		return err
	}
	if w.Format == FormatTemplate && strings.TrimSpace(w.Template) == "" {
		return fmt.Errorf("a custom body needs a template")
	}
	return nil
}

// ValidateTemplate checks the body template against the vocabulary of the events this
// webhook's triggers resolve to.
//
// Separate from Validate because it needs the trigger store to resolve a reference, and this
// type deliberately knows nothing about one — the same reason Manifest.Validate does not check
// that a trigger reference resolves. Store.Create and Store.Update call both.
func (w *Webhook) ValidateTemplate(events []string) error {
	if w.Format != FormatTemplate {
		return nil
	}
	_, err := ParseTemplate(w.Template, events)
	return err
}

func (w *Webhook) validateURL() error {
	switch {
	case w.URL == "":
		return fmt.Errorf("url is required")
	case len(w.URL) > MaxURLLen:
		return fmt.Errorf("url is %d characters, over the %d limit", len(w.URL), MaxURLLen)
	}
	u, err := url.Parse(w.URL)
	if err != nil {
		return fmt.Errorf("url %q does not parse: %w", w.URL, err)
	}
	// http and https only. A file: or a gopher: destination is not a webhook, and refusing
	// the scheme is cheaper than reasoning about what the transport would do with one.
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("url %q names no host", w.URL)
	}
	return nil
}

func (w *Webhook) validateHeaders() error {
	if len(w.Headers) > MaxHeaders {
		return fmt.Errorf("this webhook sets %d headers, over the %d limit",
			len(w.Headers), MaxHeaders)
	}
	for i, h := range w.Headers {
		switch {
		case h.Name == "":
			return fmt.Errorf("header %d has no name", i+1)
		case !headerNamePattern.MatchString(h.Name):
			return fmt.Errorf("header name %q is invalid: use letters, digits and -_.", h.Name)
		case len(h.Value) > MaxHeaderLen:
			return fmt.Errorf("header %s is %d characters, over the %d limit",
				h.Name, len(h.Value), MaxHeaderLen)
		case strings.ContainsAny(h.Value, "\r\n"):
			return fmt.Errorf("header %s contains a newline", h.Name)
		case isReservedHeader(h.Name):
			return fmt.Errorf("header %s is set by Joro on every delivery; choose another name",
				h.Name)
		}
	}
	return nil
}

// isReservedHeader reports whether Joro sets this header itself. Refused rather than
// overwritten, so an operator who typed one finds out at save time instead of wondering why
// their value never arrives.
func isReservedHeader(name string) bool {
	switch strings.ToLower(name) {
	case strings.ToLower(HeaderEvent), strings.ToLower(HeaderTrigger),
		strings.ToLower(HeaderDelivery), strings.ToLower(HeaderTimestamp),
		"content-type", "content-length", "host":
		return true
	}
	return false
}

func (w *Webhook) validateAuth() error {
	if !slices.Contains(AuthKinds, w.Auth.Kind) {
		return fmt.Errorf("auth kind %q is not one of %s", w.Auth.Kind,
			strings.Join(AuthKinds, ", "))
	}
	if len(w.Auth.Token) > MaxSecretLen {
		return fmt.Errorf("the auth secret is %d characters, over the %d limit",
			len(w.Auth.Token), MaxSecretLen)
	}
	if strings.ContainsAny(w.Auth.Token, "\r\n") || strings.ContainsAny(w.Auth.User, "\r\n") {
		return fmt.Errorf("auth credentials contain a newline")
	}
	switch w.Auth.Kind {
	case AuthBearer:
		if w.Auth.Token == "" {
			return fmt.Errorf("bearer auth needs a token")
		}
	case AuthBasic:
		if w.Auth.User == "" {
			return fmt.Errorf("basic auth needs a username")
		}
	case AuthHeader:
		switch {
		case w.Auth.Header == "":
			return fmt.Errorf("header auth needs a header name")
		case !headerNamePattern.MatchString(w.Auth.Header):
			return fmt.Errorf("auth header name %q is invalid", w.Auth.Header)
		case isReservedHeader(w.Auth.Header):
			return fmt.Errorf("header %s is set by Joro on every delivery; choose another name",
				w.Auth.Header)
		case w.Auth.Token == "":
			return fmt.Errorf("header auth needs a value")
		}
	}
	return nil
}

func (w *Webhook) validateSigning() error {
	if !w.Signing.Enabled {
		return nil
	}
	switch {
	case w.Signing.Secret == "":
		return fmt.Errorf("signing needs a secret")
	case len(w.Signing.Secret) > MaxSecretLen:
		return fmt.Errorf("the signing secret is %d characters, over the %d limit",
			len(w.Signing.Secret), MaxSecretLen)
	case !headerNamePattern.MatchString(w.Signing.Header):
		return fmt.Errorf("signature header name %q is invalid", w.Signing.Header)
	case isReservedHeader(w.Signing.Header):
		return fmt.Errorf("header %s is set by Joro on every delivery; choose another name",
			w.Signing.Header)
	}
	return nil
}

// HasSecrets reports whether this webhook holds anything the API must withhold.
func (w *Webhook) HasSecrets() bool {
	if w.Auth.Token != "" || w.Signing.Secret != "" {
		return true
	}
	for _, h := range w.Headers {
		if h.Value != "" {
			return true
		}
	}
	return false
}
