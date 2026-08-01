package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/BishopFox/joro/internal/proxy"
)

// ruleSet is an immutable snapshot of the compiled rules. Engine swaps the
// pointer under a write lock on every mutation; Scan takes the pointer under a
// read lock and releases it before scanning.
type ruleSet struct {
	byTarget  map[Target][]*Rule
	analyzers []analyzerBinding
	active    int
}

// analyzerBinding pairs an analyzer rule with its resolved function.
type analyzerBinding struct {
	rule *Rule
	fn   Analyzer
}

// Engine holds the rule set and produces findings from captured messages.
//
// Built-in rules are immutable: builtinRules() returns a fresh slice, operator
// changes are held separately as a disabled-ID set plus a severity-override map,
// and the API rejects edits and deletes of built-ins.
type Engine struct {
	mu      sync.RWMutex
	enabled bool
	cfg     Config
	builtin []Rule
	user    []Rule
	// disabled holds built-in IDs the operator switched off. Every shipped rule is
	// enabled by default, so this set plus severityOverride is the only mutable
	// state about a built-in rule.
	disabled         map[string]struct{}
	severityOverride map[string]Severity
	set              *ruleSet
}

// NewEngine returns an enabled engine with the built-in library loaded and the
// default configuration.
func NewEngine() *Engine {
	e := &Engine{
		enabled:          true,
		cfg:              DefaultConfig(),
		builtin:          builtinRules(),
		disabled:         map[string]struct{}{},
		severityOverride: map[string]Severity{},
	}
	e.mu.Lock()
	e.rebuildLocked()
	e.mu.Unlock()
	return e
}

// rebuildLocked compiles the effective rule set and swaps in the new snapshot.
// Callers must hold the write lock (or be the constructor).
//
// All per-rule resolution happens here — regex compilation, status predicate,
// post-filter lookup, content-type set, folded literal — so the scan path does
// none of it. A pattern that fails to compile leaves compiled nil and the rule
// is skipped.
func (e *Engine) rebuildLocked() {
	set := &ruleSet{byTarget: map[Target][]*Rule{}}
	add := func(r Rule) {
		if _, off := e.disabled[r.ID]; off {
			return
		}
		if sev, ok := e.severityOverride[r.ID]; ok && sev.Valid() {
			r.Severity = sev
		}
		r.Enabled = true
		if r.MaxPerResponse <= 0 {
			r.MaxPerResponse = defaultMaxPerResponse
		}
		if r.GroupBy == "" {
			r.GroupBy = GroupByEvidence
		}
		if r.StatusCodes != "" {
			r.status = proxy.NewStatusPredicate(r.StatusCodes)
		}
		if r.Literal != "" {
			r.literalLower = []byte(strings.ToLower(r.Literal))
		}
		if len(r.ContentTypes) > 0 {
			r.ctSet = make(map[string]struct{}, len(r.ContentTypes))
			for _, ct := range r.ContentTypes {
				r.ctSet[strings.ToLower(ct)] = struct{}{}
			}
		}
		if len(r.ExcludeContentTypes) > 0 {
			r.excludeCtSet = make(map[string]struct{}, len(r.ExcludeContentTypes))
			for _, ct := range r.ExcludeContentTypes {
				r.excludeCtSet[strings.ToLower(ct)] = struct{}{}
			}
		}
		r.filters = resolvePostFilters(r.PostFilters)

		switch r.Kind {
		case KindAnalyzer:
			fn, ok := analyzerRegistry[r.Analyzer]
			if !ok {
				return
			}
			rp := &r
			set.analyzers = append(set.analyzers, analyzerBinding{rule: rp, fn: fn})
			set.active++
		default:
			compiled, err := regexp.Compile(r.Pattern)
			if err != nil {
				return
			}
			r.compiled = compiled
			rp := &r
			set.byTarget[r.Target] = append(set.byTarget[r.Target], rp)
			set.active++
		}
	}
	for _, r := range e.builtin {
		if !e.ruleEnabledLocked(r) {
			continue
		}
		add(r)
	}
	for _, r := range e.user {
		if !r.Enabled {
			continue
		}
		add(r)
	}
	e.set = set
}

// IsEnabled reports whether detection is active.
func (e *Engine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// SetEnabled turns detection on or off.
func (e *Engine) SetEnabled(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = v
}

// Config returns the current configuration.
func (e *Engine) Config() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// SetConfig replaces the configuration, filling zero values with defaults.
func (e *Engine) SetConfig(cfg Config) {
	cfg.normalize()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
}

// ActiveRuleCount returns how many rules are currently compiled and live.
func (e *Engine) ActiveRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.set == nil {
		return 0
	}
	return e.set.active
}

// Rules returns every rule, built-in and user, as copies with Enabled and
// Severity resolved into one flat list.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, 0, len(e.builtin)+len(e.user))
	for _, r := range e.builtin {
		r.Enabled = e.ruleEnabledLocked(r)
		if sev, ok := e.severityOverride[r.ID]; ok && sev.Valid() {
			r.Severity = sev
		}
		out = append(out, r)
	}
	out = append(out, e.user...)
	return out
}

// ruleEnabledLocked resolves a built-in rule's effective enabled state from the
// operator's disabled set.
func (e *Engine) ruleEnabledLocked(r Rule) bool {
	_, off := e.disabled[r.ID]
	return !off
}

// RuleEnabledFunc returns a predicate over rule IDs, snapshotted into a map for
// callers filtering large finding sets. An unknown ID counts as enabled, so a
// finding whose custom rule was deleted stays visible.
func (e *Engine) RuleEnabledFunc() func(string) bool {
	enabled := make(map[string]bool)
	for _, r := range e.Rules() {
		enabled[r.ID] = r.Enabled
	}
	return func(id string) bool {
		on, known := enabled[id]
		return !known || on
	}
}

// Rule returns a single rule by ID.
func (e *Engine) Rule(id string) (Rule, bool) {
	for _, r := range e.Rules() {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// UserRules returns a copy of the operator-defined rules.
func (e *Engine) UserRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.user))
	copy(out, e.user)
	return out
}

// DisabledBuiltins returns the IDs of built-in rules the operator turned off.
func (e *Engine) DisabledBuiltins() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.disabled))
	for id := range e.disabled {
		out = append(out, id)
	}
	return out
}

// SeverityOverrides returns the operator's per-rule severity overrides.
func (e *Engine) SeverityOverrides() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]string, len(e.severityOverride))
	for id, sev := range e.severityOverride {
		out[id] = string(sev)
	}
	return out
}

// SetDisabledBuiltins replaces the disabled-rule set (project load).
func (e *Engine) SetDisabledBuiltins(ids []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disabled = make(map[string]struct{}, len(ids))
	for _, id := range ids {
		e.disabled[id] = struct{}{}
	}
	e.rebuildLocked()
}

// SetSeverityOverrides replaces the severity override map (project load).
func (e *Engine) SetSeverityOverrides(in map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.severityOverride = make(map[string]Severity, len(in))
	for id, sev := range in {
		if s := Severity(sev); s.Valid() {
			e.severityOverride[id] = s
		}
	}
	e.rebuildLocked()
}

// SetUserRules replaces all operator rules (project load).
func (e *Engine) SetUserRules(rules []Rule) {
	for i := range rules {
		rules[i].Builtin = false
		rules[i].Kind = KindRegex
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.user = rules
	e.rebuildLocked()
}

// ErrBuiltinImmutable is returned when an edit or delete targets a built-in rule.
// Built-ins accept only an enabled toggle and a severity override.
var ErrBuiltinImmutable = errors.New("built-in rules cannot be edited or deleted")

// ErrRuleNotFound is returned when no rule has the given ID.
var ErrRuleNotFound = errors.New("rule not found")

// ValidateRule checks an operator-supplied rule, returning a message suitable
// for a 400 response. The RE2 compile error is surfaced verbatim.
func ValidateRule(r *Rule) error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name is required")
	}
	if r.Kind == KindAnalyzer {
		return errors.New("analyzer rules are built in and cannot be created")
	}
	r.Kind = KindRegex
	if strings.TrimSpace(r.Pattern) == "" {
		return errors.New("pattern is required")
	}
	if _, err := regexp.Compile(r.Pattern); err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}
	if !r.Category.Valid() {
		return fmt.Errorf("unknown category %q", r.Category)
	}
	if !r.Severity.Valid() {
		return fmt.Errorf("unknown severity %q", r.Severity)
	}
	if r.Confidence == "" {
		r.Confidence = ConfidenceMedium
	}
	if !r.Confidence.Valid() {
		return fmt.Errorf("unknown confidence %q", r.Confidence)
	}
	if r.Target == "" {
		r.Target = TargetResponseBody
	}
	if r.Target == TargetMessage || !r.Target.Valid() {
		return fmt.Errorf("unknown target %q", r.Target)
	}
	if r.GroupBy == "" {
		r.GroupBy = GroupByEvidence
	}
	if !r.GroupBy.Valid() {
		return fmt.Errorf("unknown groupBy %q", r.GroupBy)
	}
	for _, name := range r.PostFilters {
		if _, ok := postFilterRegistry[name]; !ok {
			return fmt.Errorf("unknown post-filter %q", name)
		}
	}
	if r.CaptureGroup < 0 {
		return errors.New("captureGroup must not be negative")
	}
	return nil
}

// AddRule validates and appends an operator rule, returning the stored copy.
func (e *Engine) AddRule(r Rule) (Rule, error) {
	if err := ValidateRule(&r); err != nil {
		return Rule{}, err
	}
	r.ID = proxy.GenerateID()
	r.Builtin = false
	r.Enabled = true
	e.mu.Lock()
	defer e.mu.Unlock()
	e.user = append(e.user, r)
	e.rebuildLocked()
	return r, nil
}

// UpdateRule replaces an operator rule in place. The ID must be preserved:
// Finding.RuleID references it and Finding.ID derives from it.
func (e *Engine) UpdateRule(id string, r Rule) (Rule, error) {
	if err := ValidateRule(&r); err != nil {
		return Rule{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.builtin {
		if b.ID == id {
			return Rule{}, ErrBuiltinImmutable
		}
	}
	for i := range e.user {
		if e.user[i].ID != id {
			continue
		}
		r.ID = id
		r.Builtin = false
		r.Enabled = e.user[i].Enabled
		e.user[i] = r
		e.rebuildLocked()
		return r, nil
	}
	return Rule{}, ErrRuleNotFound
}

// RemoveRule deletes an operator rule.
func (e *Engine) RemoveRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.builtin {
		if b.ID == id {
			return ErrBuiltinImmutable
		}
	}
	for i := range e.user {
		if e.user[i].ID == id {
			e.user = append(e.user[:i], e.user[i+1:]...)
			e.rebuildLocked()
			return nil
		}
	}
	return ErrRuleNotFound
}

// SetRuleEnabled toggles any rule, built-in or user.
func (e *Engine) SetRuleEnabled(id string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.builtin {
		if b.ID != id {
			continue
		}
		if enabled {
			delete(e.disabled, id)
		} else {
			e.disabled[id] = struct{}{}
		}
		e.rebuildLocked()
		return nil
	}
	for i := range e.user {
		if e.user[i].ID == id {
			e.user[i].Enabled = enabled
			e.rebuildLocked()
			return nil
		}
	}
	return ErrRuleNotFound
}

// SetRuleSeverity overrides a rule's severity. Allowed on built-ins.
func (e *Engine) SetRuleSeverity(id string, sev Severity) error {
	if !sev.Valid() {
		return fmt.Errorf("unknown severity %q", sev)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.builtin {
		if b.ID == id {
			e.severityOverride[id] = sev
			e.rebuildLocked()
			return nil
		}
	}
	for i := range e.user {
		if e.user[i].ID == id {
			e.user[i].Severity = sev
			e.rebuildLocked()
			return nil
		}
	}
	return ErrRuleNotFound
}

// ResetRule clears an operator's overrides for a built-in rule.
func (e *Engine) ResetRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.builtin {
		if b.ID != id {
			continue
		}
		delete(e.severityOverride, id)
		delete(e.disabled, id)
		e.rebuildLocked()
		return nil
	}
	return ErrRuleNotFound
}

// hostExcluded reports whether findings for a host should be suppressed.
func (e *Engine) hostExcluded(host string, cfg Config) bool {
	if len(cfg.ExcludeHosts) == 0 {
		return false
	}
	lower := strings.ToLower(host)
	for _, h := range cfg.ExcludeHosts {
		if h != "" && strings.Contains(lower, strings.ToLower(h)) {
			return true
		}
	}
	return false
}

// Scan runs every live rule against a captured request and returns the findings.
// It performs no deduplication; that is Store.Upsert's job.
func (e *Engine) Scan(r *proxy.CapturedRequest, inScope proxy.ScopeFunc) []Finding {
	e.mu.RLock()
	enabled, cfg, set := e.enabled, e.cfg, e.set
	e.mu.RUnlock()

	if !enabled || set == nil || set.active == 0 || r == nil {
		return nil
	}
	m := Parse(r, cfg)
	if e.hostExcluded(m.Host, cfg) {
		return nil
	}
	if cfg.ScopeOnly && inScope != nil && !inScope(m.Host, r.Method, m.Path) {
		return nil
	}
	return e.scanMessage(m, cfg, set)
}

// ScanMessage runs the rule set against an already-parsed message. Exposed for
// tests, which build a Message directly rather than a raw capture.
func (e *Engine) ScanMessage(m *Message) []Finding {
	e.mu.RLock()
	cfg, set := e.cfg, e.set
	e.mu.RUnlock()
	if set == nil {
		return nil
	}
	return e.scanMessage(m, cfg, set)
}

func (e *Engine) scanMessage(m *Message, cfg Config, set *ruleSet) []Finding {
	var out []Finding

	for target, rules := range set.byTarget {
		if !cfg.ScanRequests &&
			(target == TargetRequestBody || target == TargetRequestHeader) {
			continue
		}
		hay := m.haystack(target)
		if len(hay) == 0 {
			continue
		}
		var lower []byte
		for _, rule := range rules {
			if !ruleGatesPass(rule, m) {
				continue
			}
			// Literal prescreen: a substring search in place of a full regex pass.
			if rule.literalLower != nil {
				if lower == nil {
					lower = m.lowerHaystack(target)
				}
				if !bytes.Contains(lower, rule.literalLower) {
					continue
				}
			}
			out = append(out, e.applyRegexRule(rule, m, target, hay)...)
		}
	}

	for _, binding := range set.analyzers {
		if !ruleGatesPass(binding.rule, m) {
			continue
		}
		rule := binding.rule
		count := 0
		binding.fn(m, func(hit AnalyzerHit) {
			if count >= rule.MaxPerResponse {
				return
			}
			count++
			out = append(out, e.newFinding(rule, m, hit))
		})
	}
	return out
}

// ruleGatesPass applies the per-message gates: status expression, scheme, and
// content type.
func ruleGatesPass(rule *Rule, m *Message) bool {
	if rule.status != nil && !rule.status(m.RespStatus) {
		return false
	}
	if rule.Scheme != "" && !strings.EqualFold(rule.Scheme, m.Scheme) {
		return false
	}
	// Exclusion is checked before the whitelist and wins outright.
	if rule.excludeCtSet != nil {
		if _, bad := rule.excludeCtSet[contentTypeKeyword(m.ContentType)]; bad {
			return false
		}
	}
	if rule.ctSet != nil {
		if _, ok := rule.ctSet[contentTypeKeyword(m.ContentType)]; !ok {
			return false
		}
	}
	return true
}

// applyRegexRule runs one pattern and builds findings from its matches.
func (e *Engine) applyRegexRule(rule *Rule, m *Message, target Target, hay []byte) []Finding {
	if rule.compiled == nil {
		return nil
	}
	matches := rule.compiled.FindAllSubmatchIndex(hay, rule.MaxPerResponse*4)
	if matches == nil {
		return nil
	}
	var out []Finding
	seen := map[string]struct{}{}
	for _, loc := range matches {
		if len(out) >= rule.MaxPerResponse {
			break
		}
		group := rule.CaptureGroup
		// Fall back to the whole match when the requested group did not
		// participate (alternation branches).
		lo, hi := loc[0], loc[1]
		if group > 0 && 2*group+1 < len(loc) && loc[2*group] >= 0 {
			lo, hi = loc[2*group], loc[2*group+1]
		}
		// Trim surrounding whitespace. Header blocks are CRLF-framed, so a pattern
		// capturing to end of line picks up a trailing \r, which would land in the
		// evidence and in the grouping hash. A left-hand trim shifts the value's
		// start, so the offset moves with it.
		full := string(hay[lo:hi])
		raw := strings.Trim(full, " \t\r\n")
		if raw == "" {
			continue
		}
		matchAt := lo + (len(full) - len(strings.TrimLeft(full, " \t\r\n")))
		if !e.matchPasses(rule, raw, matchAt, hay, m) {
			continue
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, e.newFinding(rule, m, AnalyzerHit{
			Evidence:  raw,
			Offset:    matchAt,
			OffsetIn:  target,
			OffsetLen: len(raw),
			// The raw match is the grouping dimension for evidence-grouped rules
			// and the value the operator reveals.
			rawMatch: raw,
		}))
	}
	return out
}

// matchPasses applies the per-match validators in cost order: length, entropy,
// then the named post-filters. Placeholder rejection is not universal; it is the
// opt-in "denylist" post-filter.
func (e *Engine) matchPasses(rule *Rule, raw string, offset int, hay []byte, m *Message) bool {
	if rule.MinLength > 0 && utf8.RuneCountInString(raw) < rule.MinLength {
		return false
	}
	if rule.MinEntropy > 0 && ShannonEntropy(raw) < rule.MinEntropy {
		return false
	}
	if len(rule.filters) > 0 {
		ctx := filterContext{Match: raw, Offset: offset, Hay: hay, Msg: m}
		for _, f := range rule.filters {
			if !f(ctx) {
				return false
			}
		}
	}
	return true
}

// groupDim computes the per-rule dedupe dimension.
func groupDim(rule *Rule, m *Message, hit AnalyzerHit) string {
	extra := hit.GroupExtra
	switch rule.GroupBy {
	case GroupByHost:
		return extra
	case GroupByURL:
		return m.Path + "\x00" + extra
	default: // GroupByEvidence
		basis := hit.rawMatch
		if basis == "" {
			basis = hit.Evidence
		}
		// Hash the raw value so two secrets sharing a prefix never collide, and
		// so the key itself never carries the secret.
		sum := sha256.Sum256([]byte(basis))
		return extra + "\x00" + hex.EncodeToString(sum[:8])
	}
}

// findingID builds the deterministic group hash.
func findingID(ruleID, host, dim string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + host + "\x00" + dim))
	return hex.EncodeToString(sum[:16])
}

// redact masks the middle of a value, keeping 2-4 characters at each end.
func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	keep := 4
	if len(s) < 16 {
		keep = 2
	}
	return s[:keep] + strings.Repeat("*", 6) + s[len(s)-keep:]
}

// RedactValue exposes the masking helper for the rule tester.
func RedactValue(s string) string { return redact(s) }

// truncateRaw bounds the stored raw value to maxEvidenceBytes without escaping
// it; the raw copy must be exactly what matched.
func truncateRaw(s string) string {
	if len(s) <= maxEvidenceBytes {
		return s
	}
	return s[:maxEvidenceBytes]
}

// sanitizeEvidence escapes control characters and truncates to maxEvidenceBytes.
func sanitizeEvidence(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			b.WriteString("\\x")
			const hexDigits = "0123456789abcdef"
			b.WriteByte(hexDigits[(r>>4)&0xf])
			b.WriteByte(hexDigits[r&0xf])
		default:
			b.WriteRune(r)
		}
		if b.Len() >= maxEvidenceBytes {
			return b.String()[:maxEvidenceBytes-1] + "…"
		}
	}
	return b.String()
}

// newFinding is the single constructor every detection path funnels through; it
// applies redaction, truncation, and ID derivation.
func (e *Engine) newFinding(rule *Rule, m *Message, hit AnalyzerHit) Finding {
	evidence := hit.Evidence
	var rawEvidence string
	if rule.RedactEvidence {
		basis := hit.rawMatch
		if basis == "" {
			basis = evidence
		}
		evidence = redact(basis)
		// Only populated where redaction hid something; elsewhere Evidence is
		// already the raw value.
		rawEvidence = truncateRaw(basis)
	}
	evidence = sanitizeEvidence(evidence)

	sev := rule.Severity
	if hit.Severity != "" {
		sev = hit.Severity
	}
	conf := rule.Confidence
	if hit.Confidence != "" {
		conf = hit.Confidence
	}
	// The only place a buffer-relative offset becomes an offset into the rendered
	// document. An unmappable or zero-length region yields -1.
	offsetIn := hit.OffsetIn
	if offsetIn == "" && hit.Offset > 0 {
		offsetIn = rule.Target
	}
	absOffset, part, mapped := m.absoluteOffset(offsetIn, hit.Offset)
	if !mapped || hit.OffsetLen <= 0 {
		absOffset = -1
	}
	if part == "" {
		part = partName(rule.Target)
	}

	ts := m.Req.Timestamp
	f := Finding{
		ID:             findingID(rule.ID, m.Host, groupDim(rule, m, hit)),
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		Category:       rule.Category,
		Severity:       sev,
		Confidence:     conf,
		Target:         rule.Target,
		Host:           m.Host,
		Detail:         hit.Detail,
		Evidence:       evidence,
		RawEvidence:    rawEvidence,
		EvidenceOffset: absOffset,
		EvidenceLength: hit.OffsetLen,
		EvidencePart:   part,
		FirstSeen:      ts,
		LastSeen:       ts,
		Count:          1,
		Truncated:      m.Truncated,
	}
	if m.Req != nil {
		f.Method = m.Req.Method
		f.URL = m.Req.URL
		f.RequestID = m.Req.ID
		f.Occurrences = []Occurrence{{
			RequestID: m.Req.ID, Seq: m.Req.Seq, Method: m.Req.Method,
			URL: m.Req.URL, StatusCode: m.RespStatus, Timestamp: ts,
			Offset: absOffset, Part: part,
		}}
	}
	return f
}
