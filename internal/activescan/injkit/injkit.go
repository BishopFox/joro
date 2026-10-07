// Package injkit adapts the activescan framework to the inject library: it builds a
// sender/OAST/request-list from a rule's Target and RuleDeps and mints findings, so
// each injection rule stays a payload set plus a detector. It imports both
// activescan and inject (activescan imports neither, so there is no cycle).
package injkit

import (
	"net/url"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/inject"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/httptools"
)

// PerReqTimeout bounds one probe send. It sits above the time-based payloads'
// sleep interval so a genuine delay is observed rather than cut off.
const PerReqTimeout = 20 * time.Second

// Sender builds an inject.Sender for the target from a rule's deps.
func Sender(d activescan.RuleDeps, t activescan.Target) *inject.Sender {
	return inject.NewSender(
		httptools.SendDeps{ProxyAddr: d.ProxyAddr, CA: d.CA, Store: d.Store},
		t.Scheme, t.Host, PerReqTimeout,
	)
}

// OAST returns an OAST helper, or nil when no callback domain is configured (the
// caller then skips its OAST vectors).
func OAST(d activescan.RuleDeps) *inject.OAST { return inject.NewOAST(d.Callback) }

// Requests returns the raw request bytes to fuzz: each target URL's captured bytes,
// synthesizing a bare GET when a URL carries none.
func Requests(t activescan.Target) [][]byte {
	var out [][]byte
	for _, u := range t.URLs {
		if len(u.RawReq) > 0 {
			out = append(out, u.RawReq)
			continue
		}
		if raw := synthGET(u.URL, t.Host); raw != nil {
			out = append(out, raw)
		}
	}
	return out
}

func synthGET(rawURL, host string) []byte {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return nil
	}
	target := u.Path
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	h := host
	if u.Host != "" {
		h = u.Host
	}
	return []byte("GET " + target + " HTTP/1.1\r\nHost: " + h + "\r\nConnection: close\r\n\r\n")
}

// Finding builds a detect.Finding in detect's identity space, deduped per
// (rule, host, parameter+path) so one vulnerable parameter is one finding.
func Finding(ruleID string, cat detect.Category, sev detect.Severity, name, host, method, probeURL, param, detail, evidence string) detect.Finding {
	now := time.Now()
	return detect.Finding{
		ID:             detect.FindingID(ruleID, host, param+"|"+pathOf(probeURL)),
		RuleID:         ruleID,
		RuleName:       name,
		Category:       cat,
		Severity:       sev,
		Confidence:     detect.ConfidenceHigh,
		Target:         detect.TargetMessage,
		Host:           host,
		Method:         method,
		URL:            probeURL,
		Detail:         detail,
		Evidence:       evidence,
		FirstSeen:      now,
		LastSeen:       now,
		EvidenceOffset: -1,
	}
}

func pathOf(u string) string {
	if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}
