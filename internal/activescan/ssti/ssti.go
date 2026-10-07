// Package ssti is the active server-side template injection rule. Each check
// replaces the parameter with one engine family's arithmetic polyglot and confirms
// when the computed product appears in the response.
package ssti

import (
	"context"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/injkit"
	"github.com/BishopFox/joro/internal/detect"
)

const (
	ruleID      = "ssti"
	findingRule = "activescan.ssti"
	product     = "1649858" // 1337 * 1234, distinctive and unlikely to occur naturally
)

func syntaxCheck(id, name, desc string, payloads []string) injkit.Check {
	return injkit.Check{
		ID: id, Name: name, Severity: detect.SeverityCritical, Description: desc, Payloads: payloads,
		Probe: func(pc injkit.ProbeCtx) { probe(pc, payloads) },
	}
}

var checks = []injkit.Check{
	syntaxCheck("jinja-twig", "Jinja/Twig {{…}}", "Doubled-brace expression (Jinja2, Twig, Nunjucks).", []string{`{{1337*1234}}`}),
	syntaxCheck("dollar-hash", "Freemarker/Velocity ${…}/#{…}", "Dollar/hash expression (Freemarker, Velocity, Thymeleaf).", []string{`${1337*1234}`, `#{1337*1234}`}),
	syntaxCheck("erb-jsp", "ERB/JSP <%= … %>", "Scriptlet expression (ERB, JSP, ASP).", []string{`<%= 1337*1234 %>`}),
	syntaxCheck("razor", "Razor @(…)", "Razor expression (.NET).", []string{`@(1337*1234)`}),
	syntaxCheck("smarty-mako", "Smarty/Mako/other", "Single-brace and assignment forms (Smarty, Mako, Spring EL).", []string{`{1337*1234}`, `*{1337*1234}`, `#set($x=1337*1234)$x`}),
}

type Rule struct{ *activescan.DisabledSet }

func New() *Rule { return &Rule{activescan.NewDisabledSet()} }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "Server-side template injection" }
func (*Rule) Category() detect.Category { return detect.CategorySSTI }
func (*Rule) Description() string {
	return "Injects arithmetic-expression polyglots across common template engines (Jinja, " +
		"Twig, Freemarker, Velocity, ERB, Razor and others) into each parameter; if the " +
		"computed product appears in the response, the engine evaluated the expression."
}

func (r *Rule) CatalogItems() []activescan.CatalogItem {
	return injkit.Catalog(checks, r.DisabledSet, false)
}

func (r *Rule) Run(ctx context.Context, t activescan.Target, cfg activescan.Config, deps activescan.RuleDeps, rep activescan.Reporter) error {
	injkit.RunChecks(ctx, t, cfg, deps, rep, checks, r.DisabledSet, findingRule, detect.CategorySSTI, "Server-side template injection")
	return nil
}

func probe(pc injkit.ProbeCtx, payloads []string) {
	for _, pl := range payloads {
		res := pc.Inject(pl, false)
		if res != nil && strings.Contains(string(res.Resp.Body), product) {
			pc.File(detect.SeverityCritical, "SSTI in "+pc.Point.Name,
				"payload "+pl+" produced "+product+" in the response", res.URL)
			return
		}
	}
}
