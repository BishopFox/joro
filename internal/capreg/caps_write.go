package capreg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	uuid "github.com/hashicorp/go-uuid"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/detect"
)

// Writes against the operator's own records: notes and finding triage.
//
// Both are additive or reversible by design. There is no notes.update, no
// notes.delete and no findings.delete: an agent appending a note or marking a false
// positive is contributing to the operator's record, while one editing or deleting it
// is rewriting the operator's history, and the difference matters more than the
// convenience. Notes carry an agent: author prefix for the same reason — the operator
// must be able to tell at a glance which observations were theirs.

const maxNoteContent = 16 << 10

type notesCreateArgs struct {
	Host    string `json:"host"`
	Content string `json:"content"`
}

type findingsUpdateArgs struct {
	ID            string  `json:"id"`
	FalsePositive *bool   `json:"falsePositive"`
	Notes         *string `json:"notes"`
	Severity      string  `json:"severity"`
}

type findingsCreateArgs struct {
	Host     string `json:"host"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	URL      string `json:"url"`
	Method   string `json:"method"`
	Evidence string `json:"evidence"`
	Notes    string `json:"notes"`
}

// agentFindingRuleID namespaces findings an agent reported by hand.
//
// Finding.ID is sha256(ruleID ‖ host ‖ groupDim), so a reserved rule ID is what
// keeps these in an identity space the scanner never produces — a rescan cannot
// collide with one, and the operator can tell at a glance which findings came from
// an agent rather than from a rule.
const (
	agentFindingRuleID = "agent-reported"
	maxFindingEvidence = 2 << 10
	maxFindingTitle    = 200
)

func registerWrites(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:       "notes.create",
		Class:    capability.ClassNotes,
		Title:    "Append an engagement note",
		Mutating: true,
		Description: "Add a note to the operator's engagement notes, optionally filed under a host. Use this to " +
			"record a finding, a working payload, or context worth keeping — it is the durable channel between " +
			"you and the operator, where a tool result is not. Notes are attributed to you automatically. " +
			"Existing notes cannot be edited or deleted from here.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":    {"type":"string","description":"Host to file this under, e.g. \"api.target.com\". Omit for the host-less \"General\" bucket."},
    "content": {"type":"string","description":"The note body. Plain text; newlines are preserved."}
  },
  "required":["content"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"host":"api.target.com","content":"IDOR on /v2/orders/{id}: sequential ids, no ownership check."}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args notesCreateArgs) (any, error) {
			if d.Notes == nil {
				return nil, fmt.Errorf("notes are unavailable")
			}
			content := strings.TrimSpace(args.Content)
			if content == "" {
				return nil, fmt.Errorf("content is required and must not be empty")
			}
			if len(content) > maxNoteContent {
				return nil, fmt.Errorf("content is %d bytes, over the %d byte limit; "+
					"summarize, or split across several notes", len(content), maxNoteContent)
			}
			id, err := uuid.GenerateUUID()
			if err != nil {
				return nil, fmt.Errorf("generating note id: %w", err)
			}

			// The author prefix is not decoration: it is how the operator separates
			// their own observations from an agent's when reading the notes back.
			author := "agent"
			if p.TokenName != "" {
				author = "agent:" + p.TokenName
			}
			note, err := d.Notes.CreateNote(id, strings.TrimSpace(args.Host), content, author)
			if err != nil {
				return nil, err
			}
			capability.RecordChange(ctx, "add note host=%s (%d bytes)",
				orDefault(note.Host, "General"), len(content))
			return fmt.Sprintf("created note id=%s host=%s author=%s",
				note.ID, orDefault(note.Host, "General"), note.Author), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:    "notes.hosts",
		Class: capability.ClassNotes,
		Title: "List hosts that have notes",
		Description: "The hosts the operator has filed notes under, as a plain list. Cheaper than reading every " +
			"note when you only need to know where context exists.",
		InputSchema:    json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		ArgsExample:    json.RawMessage(`{}`),
		MaxOutputBytes: 32 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, _ struct{}) (any, error) {
			if d.Notes == nil {
				return nil, fmt.Errorf("notes are unavailable")
			}
			hosts, err := d.Notes.ListHosts()
			if err != nil {
				return nil, err
			}
			if len(hosts) == 0 {
				return "(no notes yet)", nil
			}
			for i, h := range hosts {
				if h == "" {
					hosts[i] = "(General)"
				}
			}
			return strings.Join(hosts, "\n"), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "findings.create",
		Class:    capability.ClassFindings,
		Mutating: true,
		Title:    "Record a finding you confirmed",
		Description: "Record something you established by testing, which the passive scanner cannot produce: an " +
			"IDOR, an auth bypass, a business-logic flaw. It lands in the operator's Detect tab alongside " +
			"scanner findings, attributed to you. Findings are keyed on host and title, so re-reporting the " +
			"same one updates it rather than duplicating it. Use notes_create instead for an observation that " +
			"is not a vulnerability.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":     {"type":"string","description":"Affected host, e.g. \"api.target.com\"."},
    "title":    {"type":"string","description":"Short finding name, e.g. \"IDOR on /v2/orders/{id}\". This plus host is the identity."},
    "severity": {"type":"string","enum":["critical","high","medium","low","info"],"description":"critical: high-grade PII or severe compromise (RCE, auth bypass). high: credentials, API keys, low-level PII. medium: the catch-all. low: a minor weakness. info: a surface, not exploitable."},
    "category": {"type":"string","enum":["secrets","pii","credentials","access","disclosure","headers","cookies"],"description":"Defaults to access."},
    "url":      {"type":"string","description":"The URL that demonstrates it."},
    "method":   {"type":"string","description":"HTTP method that demonstrates it."},
    "evidence": {"type":"string","description":"The observation that proves it: a response fragment, a status change, an id that was not yours."},
    "notes":    {"type":"string","description":"Reproduction steps or context for the operator."}
  },
  "required":["host","title","severity","evidence"],
  "additionalProperties":false
}`),
		ArgsExample: json.RawMessage(`{"host":"api.target.com","title":"IDOR on /v2/orders/{id}","severity":"high",` +
			`"category":"access","url":"https://api.target.com/v2/orders/8292","method":"GET",` +
			`"evidence":"200 with another tenant's order; only the id changed."}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args findingsCreateArgs) (any, error) {
			if d.Findings == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			host := strings.TrimSpace(args.Host)
			title := strings.TrimSpace(args.Title)
			evidence := strings.TrimSpace(args.Evidence)
			if host == "" || title == "" || evidence == "" {
				return nil, fmt.Errorf("host, title and evidence are all required and must not be empty")
			}
			if len(title) > maxFindingTitle {
				return nil, fmt.Errorf("title is %d characters, over the %d limit; put the detail in evidence or notes",
					len(title), maxFindingTitle)
			}
			if len(evidence) > maxFindingEvidence {
				return nil, fmt.Errorf("evidence is %d bytes, over the %d byte limit; summarize, and put the "+
					"detail in notes", len(evidence), maxFindingEvidence)
			}

			sev := detect.Severity(args.Severity)
			if !sev.Valid() {
				return nil, fmt.Errorf("severity %q is not one of critical, high, medium, low, info", args.Severity)
			}
			cat := detect.Category(orDefault(args.Category, string(detect.CategoryAccess)))
			if !cat.Valid() {
				return nil, fmt.Errorf("category %q is not one of secrets, pii, credentials, access, disclosure, headers, cookies", args.Category)
			}

			author := "agent"
			if p.TokenName != "" {
				author = "agent:" + p.TokenName
			}
			now := time.Now()
			f := detect.Finding{
				ID:         detect.FindingID(agentFindingRuleID, host, title),
				RuleID:     agentFindingRuleID,
				RuleName:   title,
				Category:   cat,
				Severity:   sev,
				Confidence: detect.ConfidenceHigh,
				Target:     detect.TargetMessage,
				Host:       host,
				Method:     strings.ToUpper(strings.TrimSpace(args.Method)),
				URL:        strings.TrimSpace(args.URL),
				Detail:     "reported by " + author,
				Evidence:   evidence,
				Notes:      strings.TrimSpace(args.Notes),
				FirstSeen:  now,
				LastSeen:   now,
				// Offsets refer to a captured document; this finding has none.
				EvidenceOffset: -1,
			}
			saved, isNew := d.Findings.Upsert(f)
			capability.RecordChange(ctx, "report finding %s on %s (%s)", title, host, sev)

			broadcast(d, "detect.finding", map[string]any{"finding": saved, "isNew": isNew})
			broadcast(d, "detect.summary", d.Findings.Summary(ruleEnabledFunc(d)))

			verb := "created"
			if !isNew {
				verb = "updated existing"
			}
			return fmt.Sprintf("%s finding id=%s severity=%s host=%s", verb, saved.ID, saved.Severity, saved.Host), nil
		}),
	})

	r.MustRegister(capability.Capability{
		ID:       "findings.update",
		Class:    capability.ClassFindings,
		Title:    "Triage a finding",
		Mutating: true,
		Description: "Mark a finding as a false positive, attach notes to it, or override its severity. This is " +
			"the way to record triage conclusions where the operator will see them. Marking a false positive " +
			"hides the finding from the default view but never deletes it, and the mark survives a rescan. " +
			"Findings cannot be deleted from here.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id":            {"type":"string","description":"Finding ID, as returned by findings_list."},
    "falsePositive": {"type":"boolean","description":"Mark or unmark as a false positive."},
    "notes":         {"type":"string","description":"Replace the finding's notes. Pass an empty string to clear them."},
    "severity":      {"type":"string","enum":["critical","high","medium","low","info"],"description":"Override the rule's severity for this finding only."}
  },
  "required":["id"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"id":"a1b2c3d4e5f60718","falsePositive":true,"notes":"Example value in vendor docs, not a live key."}`),
		MaxOutputBytes: 16 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args findingsUpdateArgs) (any, error) {
			if d.Findings == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			if args.FalsePositive == nil && args.Notes == nil && args.Severity == "" {
				return nil, fmt.Errorf("nothing to do: set at least one of falsePositive, notes or severity")
			}

			var sev *detect.Severity
			if args.Severity != "" {
				s := detect.Severity(args.Severity)
				if !s.Valid() {
					return nil, fmt.Errorf("severity %q is not one of critical, high, medium, low, info", args.Severity)
				}
				sev = &s
			}
			updated, ok := d.Findings.Update(args.ID, args.FalsePositive, args.Notes, sev)
			if !ok {
				return nil, fmt.Errorf("no finding with id %s", args.ID)
			}

			var changed []string
			if args.FalsePositive != nil {
				changed = append(changed, fmt.Sprintf("falsePositive=%t", *args.FalsePositive))
			}
			if args.Notes != nil {
				changed = append(changed, fmt.Sprintf("notes=%d bytes", len(*args.Notes)))
			}
			if sev != nil {
				changed = append(changed, "severity="+string(*sev))
			}
			capability.RecordChange(ctx, "triage finding %s %s", args.ID, strings.Join(changed, " "))

			// The Detect tab listens for these, so an operator watching it sees the
			// agent's triage land rather than discovering it on reload.
			broadcast(d, "detect.summary", d.Findings.Summary(ruleEnabledFunc(d)))
			return fmt.Sprintf("updated finding %s: severity=%s falsePositive=%t notes=%d bytes",
				updated.ID, updated.Severity, updated.FalsePositive, len(updated.Notes)), nil
		}),
	})
}
