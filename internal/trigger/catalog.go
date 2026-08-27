package trigger

import (
	"slices"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/fuzzer"
	"github.com/BishopFox/joro/internal/jsruntime"
)

// The condition vocabulary: which fields each event carries, and what may be asked of
// each.
//
// Served to the editor rather than restated there, for the reason the command vocabulary
// already is — a field added here appears in the canvas's selects with no client change,
// and the client can never offer a pairing the server would refuse.

// Condition operators.
//
// A byte field's string operators all compile to one regexp rather than to their own
// comparisons. That is what makes a case-insensitive match over a megabyte body cost no
// lowercased copy of it, and it gives the literal prescreen a single place to hook into.
const (
	OpEq       = "eq"
	OpNe       = "ne"
	OpContains = "contains"
	OpPrefix   = "prefix"
	OpSuffix   = "suffix"
	OpMatches  = "matches"
	OpGlob     = "glob"
	OpIn       = "in"
	OpExists   = "exists"
	OpStatus   = "status"
	OpGt       = "gt"
	OpLt       = "lt"
	OpGte      = "gte"
	OpLte      = "lte"
)

// Field kinds. The kind decides which operators a field accepts and how its value is
// read.
const (
	KindText   = "text"
	KindBytes  = "bytes"
	KindNumber = "number"
	KindBool   = "bool"
	KindStatus = "status"
)

// Evaluation cost classes, used to order a logic node's inputs cheapest-first so that
// short-circuiting does real work. A status comparison that rejects the candidate must
// run before the regex that would have decompressed its body.
const (
	costMeta = iota
	costRaw
	costBody
)

// FieldSpec describes one condition field: what it is called, what it holds, and which
// operators it accepts.
type FieldSpec struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Ops         []string `json:"ops"`
	Description string   `json:"description"`

	// Values enumerates everything this field can hold, for a field that has a closed
	// set. The editor renders a dropdown instead of a text box, which is the difference
	// between choosing "critical" and guessing whether it is spelled "Critical".
	//
	// Advisory, not enforced: a value outside the set is still storable, because the set
	// can grow — a detect category added in a later release must not make an existing
	// trigger invalid. It narrows what the editor offers, not what the evaluator accepts.
	Values []string `json:"values,omitempty"`

	// cost orders evaluation. Not serialized: an implementation detail of the evaluator,
	// and nothing the operator chooses.
	cost int
}

// Operator sets by kind.
var (
	textOps   = []string{OpEq, OpNe, OpContains, OpPrefix, OpSuffix, OpMatches, OpGlob, OpIn, OpExists}
	bytesOps  = []string{OpContains, OpPrefix, OpSuffix, OpMatches, OpExists}
	numberOps = []string{OpEq, OpNe, OpGt, OpLt, OpGte, OpLte, OpIn, OpExists}
	statusOps = []string{OpStatus, OpEq, OpNe, OpGt, OpLt, OpGte, OpLte, OpIn, OpExists}
	boolOps   = []string{OpEq, OpNe}
)

func field(name, kind string, ops []string, cost int, desc string) FieldSpec {
	return FieldSpec{Name: name, Kind: kind, Ops: ops, Description: desc, cost: cost}
}

// enum is field with a closed set of values.
func enum(name string, ops []string, values []string, desc string) FieldSpec {
	return FieldSpec{
		Name: name, Kind: KindText, Ops: ops, Description: desc,
		Values: values, cost: costMeta,
	}
}

// The closed sets.
//
// Read from the package that owns each one wherever there is one, so a severity or an
// outcome added there appears in the editor's dropdown with nothing here to edit. The
// three below it are declared here because nothing else owns them: HTTP's method and
// version registries are not Joro's, and this is the only place either is offered as a
// choice.
var (
	severities   = names(detect.Severities)
	confidences  = names(detect.Confidences)
	categories   = names(detect.Categories)
	contentKinds = detect.ContentTypeKeywords
	outcomes     = jsruntime.Outcomes
	campaignEnd  = names(fuzzer.TerminalStatuses)

	methods   = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
	protocols = []string{"HTTP/1.1", "HTTP/2"}
	bools     = []string{"true", "false"}
)

// names renders a slice of string-kinded constants as plain strings.
func names[T ~string](in []T) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	return out
}

// eventFields is the per-event vocabulary, the same shape and the same purpose as
// jsautomation's CommandPlaceholderAvailability: which dimensions a given event can
// actually supply.
//
// An event absent from this map carries nothing to test, which is every event the
// operator starts by hand.
var eventFields = map[string][]FieldSpec{
	EventRequestCaptured: {
		enum("method", textOps, methods, "The request method."),
		field("host", KindText, textOps, costMeta, "The captured Host header, including a port when one was sent."),
		field("url", KindText, textOps, costMeta, "The full request URL."),
		field("path", KindText, textOps, costMeta, "The URL path alone, without query or host."),
		field("status", KindStatus, statusOps, costMeta, "The response status code. The status operator takes an expression: 4xx,403,500-599."),
		enum("contentType", textOps, contentKinds, "The response content type, as a keyword rather than the full MIME type."),
		enum("protocol", textOps, protocols, "Which HTTP version carried the request."),
		field("responseSize", KindNumber, numberOps, costMeta, "Response size in bytes, as captured."),
		field("durationMs", KindNumber, numberOps, costMeta, "How long the request took, in milliseconds."),
		field("request.headers", KindBytes, bytesOps, costRaw, "The request header block."),
		field("request.body", KindBytes, bytesOps, costBody, "The request body, decompressed."),
		field("request.raw", KindBytes, bytesOps, costRaw, "The whole request as captured, headers and body."),
		field("response.headers", KindBytes, bytesOps, costRaw, "The response header block."),
		field("response.body", KindBytes, bytesOps, costBody, "The response body, decompressed. Never matches a binary or brotli body."),
		field("response.raw", KindBytes, bytesOps, costRaw, "The whole response as captured, headers and body."),
	},
	EventDetectFinding: {
		enum("severity", textOps, severities, "How serious the finding is."),
		enum("confidence", textOps, confidences, "The rule's confidence in this finding."),
		enum("category", textOps, categories, "The finding's category."),
		field("ruleId", KindText, textOps, costMeta, "The rule that produced the finding."),
		field("name", KindText, textOps, costMeta, "The rule's name."),
		field("host", KindText, textOps, costMeta, "The host the finding is on."),
		field("url", KindText, textOps, costMeta, "The URL the finding is on."),
		FieldSpec{Name: "isNew", Kind: KindBool, Ops: boolOps, Values: bools,
			Description: "false when Detect has reported this finding before."},
	},
	EventFuzzerComplete: {
		field("campaignId", KindText, textOps, costMeta, "The campaign that finished."),
		enum("status", textOps, campaignEnd, "How the campaign ended."),
		field("completed", KindNumber, numberOps, costMeta, "Requests the campaign sent."),
		field("errors", KindNumber, numberOps, costMeta, "Requests that failed."),
	},
	EventAutomationComplete: {
		field("automationId", KindText, textOps, costMeta, "The automation whose run finished."),
		enum("outcome", textOps, outcomes, "The run's stable outcome code."),
		field("reason", KindText, textOps, costMeta, "The run's outcome in words."),
		field("trigger", KindText, textOps, costMeta, "What started that run."),
		field("calls", KindNumber, numberOps, costMeta, "SDK calls the run made."),
		field("sendCalls", KindNumber, numberOps, costMeta, "Calls that put bytes on the wire."),
		field("durationMs", KindNumber, numberOps, costMeta, "How long the run took."),
		field("exitCode", KindNumber, numberOps, costMeta, "A command run's exit status. Absent for a script."),
		field("value", KindBytes, bytesOps, costMeta, "The run's return value as JSON text, or a command's stdout."),
	},
}

// Fields returns the condition vocabulary for every event that carries one.
func Fields() map[string][]FieldSpec { return eventFields }

// FieldIndex returns one event's vocabulary keyed by field name, or nil when the event
// carries nothing to test.
func FieldIndex(on string) map[string]FieldSpec {
	specs, ok := eventFields[on]
	if !ok {
		return nil
	}
	out := make(map[string]FieldSpec, len(specs))
	for _, s := range specs {
		out[s.Name] = s
	}
	return out
}

// Limits is what the editor needs in order to stop adding rather than let a save fail.
type Limits struct {
	Nodes    int `json:"nodes"`
	Edges    int `json:"edges"`
	ValueLen int `json:"valueLen"`
}

// GraphLimits reports the bounds a stored graph is held to.
func GraphLimits() Limits {
	return Limits{Nodes: MaxNodes, Edges: MaxEdges, ValueLen: MaxValueLen}
}

// Ops returns every operator, for a client that wants to label them.
func Ops() []string {
	seen := map[string]bool{}
	var out []string
	for _, set := range [][]string{statusOps, textOps, bytesOps, numberOps, boolOps} {
		for _, op := range set {
			if !seen[op] {
				seen[op] = true
				out = append(out, op)
			}
		}
	}
	slices.Sort(out)
	return out
}
