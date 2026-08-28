package webhook

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BishopFox/joro/internal/trigger"
)

// The body renderer.
//
// The rule this file exists to enforce is that a body's *shape* is fixed before any event
// value reaches it. A template is a JSON document, parsed once at save time; rendering walks
// the decoded structure and substitutes only inside string leaves, then hands the result back
// to encoding/json. Three properties follow, and they are why this is a walk rather than a
// string replace over the template text:
//
//   - Escaping is total and is not a quoting rule written here. A finding name holding a
//     quote, a backslash or a control byte becomes a correctly escaped JSON string because
//     Marshal writes it, which is the same reason localcmd fills argv elements that already
//     exist rather than building a command line.
//   - A value cannot add a key, close an object, or change a number into a string. The
//     decoded template has the shape; substitution only fills it.
//   - A token in an object *key* is refused at save time rather than silently left as
//     literal text, because a key is the one position where filling it would change the
//     document's shape.
//
// Presets render without a template at all: they are the shapes an operator would otherwise
// have to look up, and a wrong guess produces a 400 from the service rather than an error
// from Joro.

// tokenPattern matches one placeholder. Names are the catalog's own field names, which are
// dotted and camelCase, plus the reserved ALL-CAPS names below — the case difference is what
// lets an operator tell at a glance which half of the vocabulary a token comes from.
var tokenPattern = regexp.MustCompile(`\{\{([A-Za-z][A-Za-z0-9_.]*)\}\}`)

// The reserved tokens, available on every event because Joro supplies them rather than the
// event doing so.
const (
	TokenEvent    = "EVENT"
	TokenTrigger  = "TRIGGER"
	TokenWebhook  = "WEBHOOK"
	TokenTime     = "TIME"
	TokenSummary  = "SUMMARY"
	TokenMessage  = "MESSAGE"
	TokenInstance = "INSTANCE"
)

// ReservedToken describes one reserved placeholder for the editor's reference table. Held
// beside the resolver that implements it, so a token cannot be documented one way and
// substituted another.
type ReservedToken struct {
	Name        string `json:"name"`
	Token       string `json:"token"`
	Description string `json:"description"`
}

// ReservedTokens describes every placeholder Joro supplies itself.
func ReservedTokens() []ReservedToken {
	return []ReservedToken{
		{TokenSummary, "{{" + TokenSummary + "}}",
			"A one-line description of what happened, composed by Joro. What the Slack and " +
				"Discord presets send."},
		{TokenEvent, "{{" + TokenEvent + "}}", "The event that fired, e.g. detect.finding."},
		{TokenTrigger, "{{" + TokenTrigger + "}}",
			"The trigger reference that matched, which distinguishes two triggers on one event."},
		{TokenWebhook, "{{" + TokenWebhook + "}}", "This webhook's name."},
		{TokenTime, "{{" + TokenTime + "}}", "When the event was matched, RFC 3339."},
		{TokenInstance, "{{" + TokenInstance + "}}", "This Joro's version."},
		{TokenMessage, "{{" + TokenMessage + "}}",
			"The message an automation passed to joro.webhook.send. Empty when an event fired " +
				"this delivery rather than a script."},
	}
}

// renderContext is everything a body may draw on for one delivery.
type renderContext struct {
	Event    string
	Trigger  string
	Webhook  string
	Instance string
	At       time.Time

	// Fields resolves the event's own vocabulary. Nil for a delivery an automation fired,
	// which carries no event.
	Fields trigger.Subject

	// Summary is Joro's one-liner. Message is what an automation passed; empty otherwise.
	Summary string
	Message string
}

func (c renderContext) resolve(name string) string {
	switch name {
	case TokenEvent:
		return c.Event
	case TokenTrigger:
		return c.Trigger
	case TokenWebhook:
		return c.Webhook
	case TokenInstance:
		return c.Instance
	case TokenTime:
		return c.At.Format(time.RFC3339)
	case TokenSummary:
		return c.Summary
	case TokenMessage:
		return c.Message
	}
	if c.Fields == nil {
		return ""
	}
	// A field the event does not carry renders empty rather than as its own literal token.
	// Ok is false for a response that was never captured or a key the payload lacks, and a
	// notification saying "{{status}}" is worse than one saying nothing.
	v := c.Fields.Value(name)
	if !v.Ok {
		return ""
	}
	return clip(fieldText(v))
}

func fieldText(v trigger.FieldValue) string {
	switch {
	case v.IsNum:
		return strconv.FormatFloat(v.Num, 'f', -1, 64)
	case v.Raw != nil:
		return string(v.Raw)
	default:
		return v.Text
	}
}

// clip bounds one substituted value. Marked when it bites, so a receiver reading a truncated
// URL is not left to wonder whether that is the whole of it.
//
// The cut is walked back off a partial rune. Marshal would substitute U+FFFD and the body
// would still be valid, but a value ending in a replacement character reads as corruption in
// the data rather than as Joro having shortened it.
func clip(s string) string {
	if len(s) <= MaxValueLen {
		return s
	}
	cut := MaxValueLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Template is a parsed body template, held so a webhook's document is decoded once per edit
// rather than once per delivery.
type Template struct {
	root any
}

// ParseTemplate decodes and checks a template against the vocabulary of the events this
// webhook watches.
//
// events is the union of what its triggers resolve to. A token valid for one of them and not
// another is accepted — host is on both a capture and a finding, severity only on a finding —
// because the alternative is refusing every template a webhook on two events could write. The
// event that does not carry it renders it empty, which the editor says beside each field.
func ParseTemplate(src string, events []string) (*Template, error) {
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("a custom body needs a template")
	}
	if len(src) > MaxTemplateLen {
		return nil, fmt.Errorf("the template is %d bytes, over the %d limit", len(src), MaxTemplateLen)
	}

	var root any
	dec := json.NewDecoder(strings.NewReader(src))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("the template is not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("the template holds more than one JSON document")
	}

	known := knownTokens(events)
	if err := checkTokens(root, known, ""); err != nil {
		return nil, err
	}
	return &Template{root: root}, nil
}

// knownTokens is every name a template may use for this webhook: the reserved set, plus each
// watched event's non-bytes fields.
//
// Bytes fields are excluded rather than clipped. request.raw and response.body are megabytes
// by design and exist so a condition can search them; putting one in a notification body is
// never what was meant, and refusing at save time says so where a 4 KB clipping would not.
func knownTokens(events []string) map[string]struct{} {
	known := map[string]struct{}{}
	for _, t := range ReservedTokens() {
		known[t.Name] = struct{}{}
	}
	for _, on := range events {
		for _, f := range trigger.Fields()[on] {
			if f.Kind == trigger.KindBytes {
				continue
			}
			known[f.Name] = struct{}{}
		}
	}
	return known
}

// SubstitutableFields lists the event fields a template may name, per event, for the editor.
func SubstitutableFields(events []string) map[string][]string {
	out := map[string][]string{}
	for _, on := range events {
		var names []string
		for _, f := range trigger.Fields()[on] {
			if f.Kind == trigger.KindBytes {
				continue
			}
			names = append(names, f.Name)
		}
		if len(names) > 0 {
			sort.Strings(names)
			out[on] = names
		}
	}
	return out
}

// checkTokens walks the decoded template, refusing an unknown token and any token in a key.
func checkTokens(node any, known map[string]struct{}, path string) error {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if tokenPattern.MatchString(k) {
				return fmt.Errorf("%s names a placeholder in a key. A placeholder fills a "+
					"value, because filling a key would change the body's shape", at(path, k))
			}
			if err := checkTokens(v[k], known, at(path, k)); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := checkTokens(item, known, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case string:
		for _, m := range tokenPattern.FindAllStringSubmatch(v, -1) {
			if _, ok := known[m[1]]; !ok {
				return fmt.Errorf("%s uses {{%s}}, which none of this webhook's events carry. "+
					"%s", label(path), m[1], hint(m[1], known))
			}
		}
	}
	return nil
}

func at(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func label(path string) string {
	if path == "" {
		return "the template"
	}
	return path
}

// hint names the closest thing the operator might have meant, which for a placeholder is
// almost always a case slip between a reserved name and a field.
func hint(name string, known map[string]struct{}) string {
	for k := range known {
		if strings.EqualFold(k, name) {
			return fmt.Sprintf("Did you mean {{%s}}?", k)
		}
	}
	return "Check the fields listed beside the editor."
}

// Render substitutes into the template and returns the body.
func (t *Template) Render(c renderContext) ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("this webhook has no template")
	}
	out, err := json.Marshal(substitute(t.root, c))
	if err != nil {
		return nil, fmt.Errorf("encoding the body: %w", err)
	}
	if len(out) > MaxBodyBytes {
		return nil, fmt.Errorf("the rendered body is %d bytes, over the %d limit",
			len(out), MaxBodyBytes)
	}
	return out, nil
}

// substitute returns a copy of node with every string leaf's placeholders filled. It builds
// new values rather than writing into the parsed template, so one delivery's substitutions
// cannot be seen by the next.
func substitute(node any, c renderContext) any {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = substitute(item, c)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, substitute(item, c))
		}
		return out
	case string:
		return tokenPattern.ReplaceAllStringFunc(v, func(tok string) string {
			return c.resolve(tok[2 : len(tok)-2])
		})
	default:
		return v
	}
}

// ---- presets ----

// renderBody produces one delivery's bytes for any format.
//
// events carries the projected references a batch delivers; it holds exactly one for
// DeliveryEach. dropped is how many the queue lost, and it rides in the envelope so a
// receiver can see it was told less than everything rather than assuming it was told all.
func renderBody(w *Webhook, tpl *Template, c renderContext, events []map[string]any, dropped int) ([]byte, error) {
	switch w.Format {
	case FormatTemplate:
		return tpl.Render(c)

	case FormatSlack:
		return marshalBounded(map[string]any{"text": c.Summary})

	case FormatDiscord:
		return marshalBounded(map[string]any{"content": c.Summary})

	default:
		env := map[string]any{
			"webhook":  w.ID,
			"event":    c.Event,
			"trigger":  c.Trigger,
			"time":     c.At.Format(time.RFC3339),
			"summary":  c.Summary,
			"instance": c.Instance,
			"events":   events,
		}
		if c.Message != "" {
			env["message"] = c.Message
		}
		if dropped > 0 {
			// Named as what it is from the receiver's side: events this webhook matched and
			// could not deliver, so a gap in the stream is visible rather than inferred.
			env["dropped"] = dropped
		}
		return marshalBounded(env)
	}
}

func marshalBounded(v any) ([]byte, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encoding the body: %w", err)
	}
	if len(out) > MaxBodyBytes {
		return nil, fmt.Errorf("the rendered body is %d bytes, over the %d limit",
			len(out), MaxBodyBytes)
	}
	return out, nil
}
