package echo

import (
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/event"
)

// ReflectionRuleID is the synthetic rule a breakout finding is filed under. It
// is not an engine rule and will not resolve in detect.Engine.Rule, so the
// human key goes in Detail and the explanation in Evidence, which is what the
// findings UI falls back to.
const ReflectionRuleID = "echo.reflection"

const reflectionRuleName = "Reflected input can leave its context"

// reconcile brings Detect's view of this engine's findings up to date: mint a
// finding for every parameter with a breakout reflection, and retract the ones
// that no longer have any.
//
// Only a breakout mints a finding. A plain reflection is not a defect — a page
// that renders what you typed is a page working correctly — and filing one per
// reflection would bury the Detect table under the ordinary behavior of every
// search box on the engagement.
func (e *Engine) reconcile(cfg Config) {
	if e.findings == nil || !cfg.Enabled {
		return
	}
	next := map[string]string{}
	changed := false

	for _, entry := range e.store.Breakouts() {
		f := entry.finding()
		sig := string(f.Severity) + "|" + f.Evidence
		next[f.ID] = sig

		e.mu.RLock()
		prev, had := e.managed[f.ID]
		e.mu.RUnlock()
		// An unchanged finding is not re-upserted: every Upsert bumps the
		// findings store revision, which feeds the autosave fingerprint, and
		// rewriting a steady finding each pass would force a project save on
		// every tick.
		if had && prev == sig {
			continue
		}
		stored, isNew := e.findings.Upsert(f)
		changed = true
		if stored != nil {
			e.emitFinding(*stored, isNew)
		}
	}

	e.mu.Lock()
	prevManaged := e.managed
	e.managed = next
	e.mu.Unlock()

	for id := range prevManaged {
		if _, still := next[id]; still {
			continue
		}
		if e.retract(id) {
			changed = true
		}
	}
	if changed && e.notify != nil {
		e.notify()
	}
}

// retract removes a finding this engine owns, unless the operator has triaged
// it. A finding someone marked a false positive or wrote a note on is theirs
// now, and deleting it would discard that work.
func (e *Engine) retract(id string) bool {
	f, ok := e.findings.Get(id)
	if !ok {
		return false
	}
	if f.FalsePositive || strings.TrimSpace(f.Notes) != "" {
		return false
	}
	return e.findings.Delete(id)
}

// retractAll drops every finding this engine owns, for when the feature is
// switched off. The map itself is kept: re-enabling should not have to rescan.
func (e *Engine) retractAll() {
	if e.findings == nil {
		return
	}
	e.mu.Lock()
	managed := e.managed
	e.managed = map[string]string{}
	e.mu.Unlock()

	changed := false
	for id := range managed {
		if e.retract(id) {
			changed = true
		}
	}
	if changed && e.notify != nil {
		e.notify()
	}
}

func (e *Engine) emitFinding(f detect.Finding, isNew bool) {
	if e.broadcast == nil {
		return
	}
	select {
	case e.broadcast <- event.WSEvent{
		Type: "detect.finding",
		Data: map[string]any{"finding": f, "isNew": isNew},
	}:
	default:
	}
}

// finding renders one map row as a detect.Finding, keyed on the parameter so
// the same parameter breaking out on many URLs is one row to triage.
func (e Entry) finding() detect.Finding {
	worst := e.worstBreakout()
	sev, conf := reflectionSeverity(worst)
	now := time.Now()

	f := detect.Finding{
		ID:             detect.FindingID(ReflectionRuleID, e.Host, string(e.Source)+":"+e.Name),
		RuleID:         ReflectionRuleID,
		RuleName:       reflectionRuleName,
		Category:       detect.CategoryReflection,
		Severity:       sev,
		Confidence:     conf,
		Target:         detect.TargetResponseBody,
		Host:           e.Host,
		URL:            e.ExampleURL,
		RequestID:      e.ExampleRequestID,
		Detail:         string(e.Source) + " parameter " + e.Name,
		Evidence:       describe(worst),
		EvidenceOffset: -1,
		FirstSeen:      now,
		LastSeen:       e.LastSeen,
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = now
	}
	// Offsets are reported only against the raw document. A decompressed body
	// shares no coordinates with it, and a Detect pane highlighting the wrong
	// bytes is worse than one highlighting none.
	if worst.Coord == "raw" && worst.Span.End > worst.Span.Start {
		f.EvidenceOffset = worst.Span.Start
		f.EvidenceLength = worst.Span.End - worst.Span.Start
		f.EvidencePart = worst.Part
	}
	return f
}

// worstBreakout picks the reflection a finding should describe: the most
// confident one that can leave its context.
func (e Entry) worstBreakout() Reflection {
	rank := map[Confidence]int{ConfidenceHigh: 0, ConfidenceMedium: 1, ConfidenceLow: 2}
	var best Reflection
	found := false
	for _, r := range e.Examples {
		if !r.Breakout {
			continue
		}
		if !found || rank[r.Confidence] < rank[best.Confidence] {
			best, found = r, true
		}
	}
	return best
}

// reflectionSeverity grades a breakout by what the context lets it reach. A
// header break is a split response, which affects every client on the path; a
// script or markup break is confined to the page.
func reflectionSeverity(r Reflection) (detect.Severity, detect.Confidence) {
	conf := detect.ConfidenceMedium
	switch r.Confidence {
	case ConfidenceHigh:
		conf = detect.ConfidenceHigh
	case ConfidenceLow:
		conf = detect.ConfidenceLow
	}
	switch r.Context {
	case ContextHeaderValue:
		return detect.SeverityHigh, conf
	case ContextScript, ContextHTMLText, ContextAttrValue, ContextTagName, ContextAttrName:
		return detect.SeverityMedium, conf
	case ContextStyle, ContextHTMLComment, ContextJSONString, ContextJSONKey:
		return detect.SeverityLow, conf
	}
	return detect.SeverityInfo, conf
}

// describe renders the one sentence that tells an operator what to do next.
func describe(r Reflection) string {
	var b strings.Builder
	b.WriteString("reflected ")
	if r.Transform == TransformIdentity {
		b.WriteString("unencoded")
	} else {
		b.WriteString(string(r.Transform) + "-encoded")
	}
	b.WriteString(" into ")
	switch r.Context {
	case ContextAttrValue:
		if r.Quote == "" {
			b.WriteString("an unquoted " + r.Attr + " attribute")
		} else {
			b.WriteString("the " + r.Quote + "-quoted " + r.Attr + " attribute")
		}
	case ContextScript:
		if r.JSContext == JSCode || r.JSContext == "" {
			b.WriteString("script code")
		} else {
			b.WriteString("a script " + strings.ReplaceAll(string(r.JSContext), "_", " "))
		}
	case ContextHeaderValue:
		b.WriteString("a response header")
	default:
		b.WriteString(strings.ReplaceAll(string(r.Context), "_", " "))
	}
	if r.Survived != "" {
		b.WriteString("; " + quoteChars(r.Survived) + " survived")
	}
	return b.String()
}

// quoteChars renders surviving characters readably, naming the ones that have
// no printable form.
func quoteChars(s string) string {
	parts := make([]string, 0, len(s))
	for _, c := range []byte(s) {
		switch c {
		case '\n':
			parts = append(parts, "LF")
		case '\r':
			parts = append(parts, "CR")
		default:
			parts = append(parts, string(c))
		}
	}
	return strings.Join(parts, " ")
}
