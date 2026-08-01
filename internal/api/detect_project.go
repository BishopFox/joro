package api

import (
	"sort"
	"time"

	"github.com/BishopFox/joro/internal/detect"
)

// maxPersistedFindings bounds how many findings ride in a project file. At
// roughly 400 bytes of JSON each, the full allowance is about 1.5 MB pre-gzip.
const maxPersistedFindings = 2000

// maxPersistedOccurrences trims the sighting list per finding for storage.
const maxPersistedOccurrences = 5

// detectStateForProject snapshots the live detection state into project DTOs.
func (s *APIServer) detectStateForProject() (
	enabled bool,
	cfg *projectDetectConfig,
	disabled []string,
	overrides map[string]string,
	rules []projectDetectRule,
	findings []projectDetectFinding,
) {
	if s.detectEngine == nil {
		return false, nil, nil, nil, nil, nil
	}

	enabled = s.detectEngine.IsEnabled()
	c := s.detectEngine.Config()
	cfg = &projectDetectConfig{
		ScopeOnly:                c.ScopeOnly,
		ScanRequests:             c.ScanRequests,
		PersistFindings:          c.PersistFindings,
		ClearFindingsWithHistory: c.ClearFindingsWithHistory,
		MaxBodyScanBytes:         c.MaxBodyScanBytes,
		MaxRequestBodyScanBytes:  c.MaxRequestBodyScanBytes,
		SkipContentTypes:         c.SkipContentTypes,
		SkipExtensions:           c.SkipExtensions,
		ExcludeHosts:             c.ExcludeHosts,
	}

	// Sorted so a project file is stable across saves and diffs cleanly.
	disabled = s.detectEngine.DisabledBuiltins()
	sort.Strings(disabled)
	overrides = s.detectEngine.SeverityOverrides()

	for _, r := range s.detectEngine.UserRules() {
		rules = append(rules, projectDetectRule{
			ID: r.ID, Name: r.Name, Description: r.Description, Remediation: r.Remediation,
			Category: string(r.Category), Severity: string(r.Severity),
			Confidence: string(r.Confidence), Target: string(r.Target),
			Pattern: r.Pattern, Literal: r.Literal, CaptureGroup: r.CaptureGroup,
			PostFilters: r.PostFilters, GroupBy: string(r.GroupBy),
			ContentTypes: r.ContentTypes, StatusCodes: r.StatusCodes, Scheme: r.Scheme,
			MinLength: r.MinLength, MinEntropy: r.MinEntropy,
			MaxPerResponse: r.MaxPerResponse, RedactEvidence: r.RedactEvidence,
			Enabled: r.Enabled,
		})
	}

	if c.PersistFindings && s.detectFindings != nil {
		findings = persistableFindings(s.detectFindings.All())
	}
	return enabled, cfg, disabled, overrides, rules, findings
}

// persistableFindings selects and trims findings for storage. Triaged findings
// (false-positive marks and notes) are always kept when the list is capped,
// regardless of severity.
func persistableFindings(all []detect.Finding) []projectDetectFinding {
	triaged := make([]detect.Finding, 0, len(all))
	rest := make([]detect.Finding, 0, len(all))
	for _, f := range all {
		if f.FalsePositive || f.Notes != "" {
			triaged = append(triaged, f)
			continue
		}
		rest = append(rest, f)
	}

	// Highest severity first, then most recently seen.
	sort.SliceStable(rest, func(i, j int) bool {
		if a, b := rest[i].Severity.Rank(), rest[j].Severity.Rank(); a != b {
			return a > b
		}
		return rest[i].LastSeen.After(rest[j].LastSeen)
	})

	selected := triaged
	for _, f := range rest {
		if len(selected) >= maxPersistedFindings {
			break
		}
		selected = append(selected, f)
	}

	out := make([]projectDetectFinding, 0, len(selected))
	for _, f := range selected {
		occ := f.Occurrences
		if len(occ) > maxPersistedOccurrences {
			occ = occ[len(occ)-maxPersistedOccurrences:]
		}
		pOcc := make([]projectDetectOccurrence, 0, len(occ))
		for _, o := range occ {
			pOcc = append(pOcc, projectDetectOccurrence{
				RequestID: o.RequestID, Seq: o.Seq, Method: o.Method, URL: o.URL,
				StatusCode: o.StatusCode, Timestamp: o.Timestamp.Format(time.RFC3339Nano),
				Offset: o.Offset, Part: o.Part,
			})
		}
		out = append(out, projectDetectFinding{
			ID: f.ID, RuleID: f.RuleID, RuleName: f.RuleName,
			Category: string(f.Category), Severity: string(f.Severity),
			Confidence: string(f.Confidence), Target: string(f.Target),
			Host: f.Host, Method: f.Method, URL: f.URL, RequestID: f.RequestID,
			Detail: f.Detail, Evidence: f.Evidence, RawEvidence: f.RawEvidence,
			EvidenceOffset: f.EvidenceOffset, EvidenceLength: f.EvidenceLength,
			EvidencePart: f.EvidencePart,
			FirstSeen:    f.FirstSeen.Format(time.RFC3339Nano),
			LastSeen:     f.LastSeen.Format(time.RFC3339Nano),
			Count:        f.Count, FalsePositive: f.FalsePositive, Notes: f.Notes,
			Truncated: f.Truncated, SeverityOverridden: f.SeverityOverridden,
			Occurrences: pOcc,
		})
	}
	return out
}

// applyDetectProjectConfig restores detection state from a project file. Returns
// the values the load response reports back to the frontend.
func (s *APIServer) applyDetectProjectConfig(cfg *projectConfigFile) map[string]any {
	if s.detectEngine == nil {
		return nil
	}

	s.detectEngine.SetEnabled(cfg.DetectEnabled)

	dc := detect.DefaultConfig()
	if cfg.DetectConfig != nil {
		p := cfg.DetectConfig
		dc = detect.Config{
			ScopeOnly:                p.ScopeOnly,
			ScanRequests:             p.ScanRequests,
			PersistFindings:          p.PersistFindings,
			ClearFindingsWithHistory: p.ClearFindingsWithHistory,
			MaxBodyScanBytes:         p.MaxBodyScanBytes,
			MaxRequestBodyScanBytes:  p.MaxRequestBodyScanBytes,
			SkipContentTypes:         p.SkipContentTypes,
			SkipExtensions:           p.SkipExtensions,
			ExcludeHosts:             p.ExcludeHosts,
		}
	}
	s.detectEngine.SetConfig(dc)

	rules := make([]detect.Rule, 0, len(cfg.DetectRules))
	for _, r := range cfg.DetectRules {
		rules = append(rules, detect.Rule{
			// The ID is preserved; findings reference it.
			ID: r.ID, Name: r.Name, Description: r.Description, Remediation: r.Remediation,
			Kind: detect.KindRegex, Category: detect.Category(r.Category),
			Severity: detect.Severity(r.Severity), Confidence: detect.Confidence(r.Confidence),
			Target: detect.Target(r.Target), Pattern: r.Pattern, Literal: r.Literal,
			CaptureGroup: r.CaptureGroup, PostFilters: r.PostFilters,
			GroupBy: detect.GroupBy(r.GroupBy), ContentTypes: r.ContentTypes,
			StatusCodes: r.StatusCodes, Scheme: r.Scheme, MinLength: r.MinLength,
			MinEntropy: r.MinEntropy, MaxPerResponse: r.MaxPerResponse,
			RedactEvidence: r.RedactEvidence, Enabled: r.Enabled,
		})
	}
	s.detectEngine.SetUserRules(rules)
	s.detectEngine.SetDisabledBuiltins(cfg.DetectDisabledRules)
	s.detectEngine.SetSeverityOverrides(cfg.DetectSeverityOverrides)

	if s.detectFindings != nil {
		s.detectFindings.Load(decodePersistedFindings(cfg.DetectFindings))
	}

	// The load response carries a finding count, not the findings themselves; the
	// frontend paginates GET /detect/findings.
	return map[string]any{
		"detectEnabled":           cfg.DetectEnabled,
		"detectConfig":            s.detectEngine.Config(),
		"detectRules":             s.detectEngine.UserRules(),
		"detectDisabledRules":     s.detectEngine.DisabledBuiltins(),
		"detectSeverityOverrides": s.detectEngine.SeverityOverrides(),
		"detectFindingCount":      len(cfg.DetectFindings),
	}
}

// decodePersistedFindings rebuilds findings from project DTOs.
func decodePersistedFindings(in []projectDetectFinding) []detect.Finding {
	out := make([]detect.Finding, 0, len(in))
	for _, p := range in {
		first, _ := time.Parse(time.RFC3339Nano, p.FirstSeen)
		last, _ := time.Parse(time.RFC3339Nano, p.LastSeen)
		occ := make([]detect.Occurrence, 0, len(p.Occurrences))
		for _, o := range p.Occurrences {
			ts, _ := time.Parse(time.RFC3339Nano, o.Timestamp)
			occ = append(occ, detect.Occurrence{
				RequestID: o.RequestID, Seq: o.Seq, Method: o.Method, URL: o.URL,
				StatusCode: o.StatusCode, Timestamp: ts, Offset: o.Offset, Part: o.Part,
			})
		}
		out = append(out, detect.Finding{
			ID: p.ID, RuleID: p.RuleID, RuleName: p.RuleName,
			Category: detect.Category(p.Category), Severity: detect.Severity(p.Severity),
			Confidence: detect.Confidence(p.Confidence), Target: detect.Target(p.Target),
			Host: p.Host, Method: p.Method, URL: p.URL, RequestID: p.RequestID,
			Detail: p.Detail, Evidence: p.Evidence, RawEvidence: p.RawEvidence,
			EvidenceOffset: p.EvidenceOffset, EvidenceLength: p.EvidenceLength,
			EvidencePart: p.EvidencePart,
			FirstSeen:    first, LastSeen: last, Count: p.Count,
			FalsePositive: p.FalsePositive, Notes: p.Notes, Truncated: p.Truncated,
			SeverityOverridden: p.SeverityOverridden, Occurrences: occ,
		})
	}
	return out
}

// resetDetectLiveState restores detection to shipped defaults for a fresh
// project: built-ins return to the default-enabled table.
func (s *APIServer) resetDetectLiveState() {
	if s.detectEngine == nil {
		return
	}
	s.detectEngine.SetEnabled(true)
	s.detectEngine.SetConfig(detect.DefaultConfig())
	s.detectEngine.SetUserRules(nil)
	s.detectEngine.SetDisabledBuiltins(nil)
	s.detectEngine.SetSeverityOverrides(nil)
	if s.detectFindings != nil {
		s.detectFindings.Clear()
	}
	s.resetDetectCursor(0)
}

// detectSignature contributes to the auto-save fingerprint. It includes the
// findings store's revision counter: the rest of the fingerprint is built from
// counts, and a false-positive toggle or note edit changes no count.
func (s *APIServer) detectSignature() string {
	if s.detectEngine == nil || s.detectFindings == nil {
		return ""
	}
	return "/dr" + itoa(len(s.detectEngine.UserRules())) +
		"/dd" + itoa(len(s.detectEngine.DisabledBuiltins())) +
		"/df" + itoa(s.detectFindings.Count()) +
		"/dg" + utoa(s.detectFindings.Revision())
}

// itoa and utoa keep detectSignature free of a fmt dependency.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func utoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
