// Package openredirect is the active open-redirect rule. Each check replaces the
// parameter with an external canary URL and confirms a redirect to that host via the
// Location header or an in-body meta/JS redirect.
package openredirect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/injkit"
	"github.com/BishopFox/joro/internal/detect"
)

const (
	ruleID      = "openredirect"
	findingRule = "activescan.openredirect"
)

func payloads(canary string) []string {
	return []string{"https://" + canary + "/", "//" + canary + "/"}
}

var checks = []injkit.Check{
	{
		ID: "location", Name: "Location header", Severity: detect.SeverityMedium,
		Description: "Injects an external URL and reports when a 3xx Location header points to it.",
		Payloads:    []string{"https://<canary>/", "//<canary>/"},
		Probe:       locationHeader,
	},
	{
		ID: "body", Name: "Body meta/JS redirect", Severity: detect.SeverityMedium,
		Description: "Injects an external URL and reports when the body redirects to it (meta refresh or window.location).",
		Payloads:    []string{"https://<canary>/", "//<canary>/"},
		Probe:       bodyRedirect,
	},
}

var bodyRedirectRe = regexp.MustCompile(`(?i)(?:http-equiv=["']?refresh|location\.(?:href|replace|assign)|window\.location)`)

type Rule struct{ *activescan.DisabledSet }

func New() *Rule { return &Rule{activescan.NewDisabledSet()} }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "Open redirect" }
func (*Rule) Category() detect.Category { return detect.CategoryOpenRedirect }
func (*Rule) Description() string {
	return "Replaces each parameter with an external canary URL and reports when the response " +
		"redirects to that host — via the Location header on a 3xx or an in-body meta/JavaScript " +
		"redirect — indicating an unvalidated redirect."
}

func (r *Rule) CatalogItems() []activescan.CatalogItem {
	return injkit.Catalog(checks, r.DisabledSet, false)
}

func (r *Rule) Run(ctx context.Context, t activescan.Target, cfg activescan.Config, deps activescan.RuleDeps, rep activescan.Reporter) error {
	injkit.RunChecks(ctx, t, cfg, deps, rep, checks, r.DisabledSet, findingRule, detect.CategoryOpenRedirect, "Open redirect")
	return nil
}

func locationHeader(pc injkit.ProbeCtx) {
	canary := "joro-redir-" + randHex(5) + ".example"
	for _, pl := range payloads(canary) {
		res := pc.Inject(pl, false)
		if res == nil {
			continue
		}
		loc := res.Resp.Header.Get("Location")
		if res.Status >= 300 && res.Status < 400 && strings.Contains(loc, canary) {
			pc.File(detect.SeverityMedium, "open redirect in "+pc.Point.Name+" (Location header)", "Location: "+loc, res.URL)
			return
		}
	}
}

func bodyRedirect(pc injkit.ProbeCtx) {
	canary := "joro-redir-" + randHex(5) + ".example"
	for _, pl := range payloads(canary) {
		res := pc.Inject(pl, false)
		if res == nil {
			continue
		}
		if strings.Contains(string(res.Resp.Body), canary) && bodyRedirectRe.Match(res.Resp.Body) {
			pc.File(detect.SeverityMedium, "open redirect in "+pc.Point.Name+" (body redirect)", "response body redirects to "+canary, res.URL)
			return
		}
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
