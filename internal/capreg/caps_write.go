package capreg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	uuid "github.com/hashicorp/go-uuid"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/detect"
)

// Writes against the operator's own records: notes and finding triage.
//
// Every write here is additive, or retractable by whoever made it. An agent may delete
// a note it filed and a finding it reported, so that superseding its own observation is
// one call rather than work left on the operator's desk. It may not touch a note the
// operator wrote or a finding the scanner produced: appending to the operator's record
// is contributing to it, while editing or deleting it is rewriting their history, and
// that difference matters more than the convenience. There is no notes.update — a note
// is retracted and refiled, not silently reworded.
//
// The one exception is a finding already marked a false positive, which any agent may
// delete regardless of who reported it. The mark is the operator's own judgment that the
// finding is noise, so clearing it destroys nothing they still rely on, and an agent that
// worked a triage backlog can tidy up behind itself.
//
// What makes that boundary checkable rather than advisory is that both artifacts record
// their origin. Notes carry an agent: author prefix, which is also how the operator tells
// at a glance which observations were theirs; agent findings carry the reserved
// agentFindingRuleID. Neither is decoration — each is read back before a delete is
// allowed.

const maxNoteContent = 16 << 10

type notesCreateArgs struct {
	Host    string `json:"host"`
	Content string `json:"content"`
}

type notesDeleteArgs struct {
	ID string `json:"id"`
}

type findingsDeleteArgs struct {
	ID             string `json:"id"`
	FalsePositives bool   `json:"falsePositives"`
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

// agentAuthor names the caller in the operator's records.
//
// It is what an agent's writes are attributed to and what its deletes are checked
// against, so the two cannot disagree about who filed something. A principal with no
// token name — the operator's own UI request, or a run nothing launched — is a bare
// "agent", which consequently owns every other such artifact. That is the honest
// reading: those callers are not distinguishable from each other, so authorship cannot
// pretend they are.
func agentAuthor(p capability.Principal) string {
	if p.TokenName == "" {
		return "agent"
	}
	return "agent:" + p.TokenName
}

func registerWrites(r *capability.Registry, d Deps) {
	r.MustRegister(capability.Capability{
		ID:       "notes.create",
		Class:    capability.ClassNotes,
		Title:    "Append an engagement note",
		Mutating: true,
		Description: "Add a note to the operator's engagement notes, optionally filed under a host. Use this to " +
			"record a finding, a working payload, or context worth keeping — it is the durable channel between " +
			"you and the operator, where a tool result is not. Notes are attributed to you automatically, and " +
			"one you filed can be withdrawn with notes_delete. Notes cannot be edited: supersede one by " +
			"deleting it and filing the replacement. The operator's own notes are not yours to change.",
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
			// their own observations from an agent's when reading the notes back, and
			// what notes.delete reads to decide whether this caller filed it.
			note, err := d.Notes.CreateNote(id, strings.TrimSpace(args.Host), content, agentAuthor(p))
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
		ID:       "notes.delete",
		Class:    capability.ClassNotes,
		Title:    "Withdraw a note you filed",
		Mutating: true,
		Description: "Delete a note you filed, by ID. Use it when an observation you recorded turns out to be " +
			"wrong or has been superseded — withdraw it and file the replacement, rather than leaving the " +
			"operator to reconcile two. Only notes attributed to you can be deleted; the operator's own notes " +
			"and those of other agents are refused. notes_list shows the author of each note.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id": {"type":"string","description":"Note ID, as returned by notes_create or notes_list."}
  },
  "required":["id"],
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"id":"5f2c1a90-6b3e-4c7d-9a11-8e0f2d4b6c83"}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, p capability.Principal, args notesDeleteArgs) (any, error) {
			if d.Notes == nil {
				return nil, fmt.Errorf("notes are unavailable")
			}
			id := strings.TrimSpace(args.ID)
			if id == "" {
				return nil, fmt.Errorf("id is required and must not be empty")
			}
			note, err := d.Notes.GetNote(id)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil, fmt.Errorf("no note with id %s", id)
				}
				return nil, err
			}
			// Read the author back rather than trusting the caller's claim: this is the
			// whole boundary between an agent retracting its own record and an agent
			// editing the operator's.
			if author := agentAuthor(p); note.Author != author {
				return nil, fmt.Errorf("note %s was filed by %q, not by you (%q); only its author can "+
					"withdraw it", id, note.Author, author)
			}
			if err := d.Notes.DeleteNote(id); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil, fmt.Errorf("no note with id %s", id)
				}
				return nil, err
			}
			capability.RecordChange(ctx, "delete note host=%s (%d bytes)",
				orDefault(note.Host, "General"), len(note.Content))
			return fmt.Sprintf("deleted note id=%s host=%s", id, orDefault(note.Host, "General")), nil
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

			author := agentAuthor(p)
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
			"Prefer marking over deleting: the mark is a triage record, where a deletion leaves nothing behind. " +
			"Use findings_delete when a finding should be gone rather than dismissed.",
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

	// Note the asymmetry with notes.delete, which is exact about authorship. A Finding's
	// only trace of who reported it is the display text in Detail, and an authorization
	// decision must not rest on a formatted string — so the check here is the reserved
	// rule ID, which is a real identity space. The consequence is that one agent can
	// delete another's reported findings. The boundary that matters holds either way:
	// what the scanner produced, and what the operator has not dismissed, is refused.
	r.MustRegister(capability.Capability{
		ID:       "findings.delete",
		Class:    capability.ClassFindings,
		Title:    "Delete a finding you reported, or dismissed noise",
		Mutating: true,
		Description: "Delete a finding, by ID, or clear every finding already marked a false positive. Use it to " +
			"retract something you reported and then disproved, or to tidy up a triage backlog you worked " +
			"through. Two things can be deleted: a finding you reported with findings_create, and any finding " +
			"marked a false positive — the mark is the operator's own judgment that it is noise. A live scanner " +
			"finding is refused; mark it a false positive with findings_update first if it should go. Deletion " +
			"leaves no record, so prefer the mark when the conclusion itself is worth keeping.",
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id":             {"type":"string","description":"Finding ID, as returned by findings_create or findings_list. Omit when using falsePositives."},
    "falsePositives": {"type":"boolean","description":"Delete every finding currently marked a false positive, whoever reported it. Mutually exclusive with id."}
  },
  "additionalProperties":false
}`),
		ArgsExample:    json.RawMessage(`{"id":"a1b2c3d4e5f60718"}`),
		MaxOutputBytes: 8 << 10,
		Handler: capability.Typed(func(ctx context.Context, _ capability.Principal, args findingsDeleteArgs) (any, error) {
			if d.Findings == nil {
				return nil, fmt.Errorf("detection is unavailable")
			}
			id := strings.TrimSpace(args.ID)
			switch {
			case id == "" && !args.FalsePositives:
				return nil, fmt.Errorf("nothing to do: set id to delete one finding, or falsePositives to " +
					"clear every finding marked a false positive")
			case id != "" && args.FalsePositives:
				return nil, fmt.Errorf("set either id or falsePositives, not both")
			}

			if args.FalsePositives {
				n := d.Findings.DeleteFalsePositives()
				if n == 0 {
					return "no findings are marked as false positives; nothing deleted", nil
				}
				capability.RecordChange(ctx, "delete %d false-positive findings", n)
				broadcast(d, "detect.findings.cleared", map[string]any{"deleted": n})
				broadcast(d, "detect.summary", d.Findings.Summary(ruleEnabledFunc(d)))
				return fmt.Sprintf("deleted %d findings marked as false positives", n), nil
			}

			f, ok := d.Findings.Get(id)
			if !ok {
				return nil, fmt.Errorf("no finding with id %s", id)
			}
			if f.RuleID != agentFindingRuleID && !f.FalsePositive {
				return nil, fmt.Errorf("finding %s was produced by rule %s and is not marked a false "+
					"positive, so it is not yours to delete; mark it with findings_update "+
					"{\"id\":%q,\"falsePositive\":true} if it should go", id, f.RuleID, id)
			}
			if !d.Findings.Delete(id) {
				return nil, fmt.Errorf("no finding with id %s", id)
			}
			capability.RecordChange(ctx, "delete finding %s on %s (%s)", f.RuleName, f.Host, f.Severity)

			// Same reason findings.update broadcasts: an operator watching the Detect tab
			// should see the agent's deletion land rather than find it on reload.
			broadcast(d, "detect.summary", d.Findings.Summary(ruleEnabledFunc(d)))
			return fmt.Sprintf("deleted finding id=%s severity=%s host=%s rule=%s",
				id, f.Severity, f.Host, f.RuleID), nil
		}),
	})
}
