// Package reflectedxss is the active reflected-XSS rule. Each check injects a unique
// canary with a particular breakout payload and reuses internal/echo's analyzer
// (enumeration, context classification, breakout rubric) on the (mutated request,
// response) pair; a reflection that breaks out of its context is a finding.
package reflectedxss

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/injkit"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/echo"
	"github.com/BishopFox/joro/internal/proxy"
)

const (
	ruleID      = "reflectedxss"
	findingRule = "activescan.reflectedxss"
)

func styleCheck(id, name, desc, suffix string) injkit.Check {
	return injkit.Check{
		ID: id, Name: name, Severity: detect.SeverityHigh, Description: desc,
		Payloads: []string{"<canary>" + suffix},
		Probe:    func(pc injkit.ProbeCtx) { probe(pc, suffix) },
	}
}

var checks = []injkit.Check{
	styleCheck("html-text", "HTML text breakout", "Breaks out of HTML text/attribute with angle brackets and quotes.", `"'></`),
	styleCheck("attribute", "Attribute event-handler", "Breaks out of an attribute into an event handler.", `" autofocus onfocus=jo `),
	styleCheck("script", "Script string breakout", "Breaks out of a JavaScript string context.", `';jo//`),
	styleCheck("template", "Template/backtick breakout", "Breaks out of a template-literal/backtick context.", "`+jo+`"),
}

type Rule struct{ *activescan.DisabledSet }

func New() *Rule { return &Rule{activescan.NewDisabledSet()} }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "Reflected XSS" }
func (*Rule) Category() detect.Category { return detect.CategoryReflectedXSS }
func (*Rule) Description() string {
	return "Injects a unique canary with HTML/JS-breaking characters into each request " +
		"parameter and reuses the Echo analyzer to decide whether it reflects into an " +
		"exploitable, unescaped context (a breakout) — confirmed reflected cross-site scripting."
}

func (r *Rule) CatalogItems() []activescan.CatalogItem {
	return injkit.Catalog(checks, r.DisabledSet, false)
}

func (r *Rule) Run(ctx context.Context, t activescan.Target, cfg activescan.Config, deps activescan.RuleDeps, rep activescan.Reporter) error {
	injkit.RunChecks(ctx, t, cfg, deps, rep, checks, r.DisabledSet, findingRule, detect.CategoryReflectedXSS, "Reflected XSS")
	return nil
}

func probe(pc injkit.ProbeCtx, suffix string) {
	canary := "joro" + randHex(5)
	res := pc.Inject(canary+suffix, false)
	if res == nil {
		return
	}
	cr := &proxy.CapturedRequest{ReqRaw: res.RawReq, RespRaw: res.RespRaw, Host: pc.Host, URL: res.URL, Method: res.Method}
	report := echo.Analyze(cr, echo.DefaultConfig())
	for _, refl := range report.Reflections {
		if refl.Breakout && strings.Contains(refl.Value, canary) {
			pc.File(detect.SeverityHigh, "parameter "+pc.Point.Name+" reflects unescaped into "+string(refl.Context),
				"canary broke out of the "+string(refl.Context)+" context; surviving characters: "+refl.Survived, res.URL)
			return
		}
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
