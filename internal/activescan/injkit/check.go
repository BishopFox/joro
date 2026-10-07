package injkit

import (
	"context"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/activescan/inject"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/httptools"
)

// SameStructure and LooksDelayed re-export the inject differential/timing helpers so
// a rule imports only injkit.
func SameStructure(a, b httptools.Fingerprint) bool { return inject.SameStructure(a, b) }
func LooksDelayed(elapsedMs, floorMs, delayMs int64) bool {
	return inject.LooksDelayed(elapsedMs, floorMs, delayMs)
}

// Check is one named, toggleable detection within an injection rule — the catalog
// row the operator sees. Metadata is static (so checks are package-level vars); the
// probe takes its run context as a parameter rather than closing over it.
type Check struct {
	ID          string
	Name        string
	Severity    detect.Severity
	Description string
	// Payloads are shown in the catalog detail; the probe is free to derive more.
	Payloads []string
	// RequiresOAST marks a check that only runs with a callback listener configured.
	RequiresOAST bool
	Probe        func(pc ProbeCtx)
}

// ProbeCtx bundles everything a check's probe needs for one insertion point.
type ProbeCtx struct {
	Ctx   context.Context
	Send  *inject.Sender
	OAST  *inject.OAST // nil when OAST is unavailable or opted out
	Host  string
	Point inject.Point
	Base  *inject.Baseline
	// File mints a finding for this point; Host/Method/URL are filled in for you.
	File func(sev detect.Severity, detail, evidence, url string)
}

// Inject mutates the point's value with payload (append or replace) and sends the
// result, returning nil on any mutation/send error so a probe can keep going.
func (pc ProbeCtx) Inject(payload string, appendMode bool) *inject.Result {
	mut, err := inject.Mutate(pc.Base.RawReq, pc.Point, payload, appendMode)
	if err != nil {
		return nil
	}
	res, err := pc.Send.Send(pc.Ctx, mut)
	if err != nil {
		return nil
	}
	return res
}

// Catalog builds the catalog items for a rule's checks, reflecting the disabled set.
func Catalog(checks []Check, disabled *activescan.DisabledSet, oastAvailable bool) []activescan.CatalogItem {
	out := make([]activescan.CatalogItem, 0, len(checks))
	for _, c := range checks {
		detail := []activescan.CatalogField{{Label: "Detection", Value: c.Name}}
		if len(c.Payloads) > 0 {
			detail = append(detail, activescan.CatalogField{Label: "Payloads", Value: strings.Join(c.Payloads, "\n")})
		}
		if c.RequiresOAST {
			avail := "requires a configured callback listener"
			if oastAvailable {
				avail = "callback listener configured"
			}
			detail = append(detail, activescan.CatalogField{Label: "Out-of-band", Value: avail})
		}
		out = append(out, activescan.CatalogItem{
			ID:          c.ID,
			Name:        c.Name,
			Severity:    string(c.Severity),
			Confidence:  string(detect.ConfidenceHigh),
			Target:      string(detect.TargetMessage),
			Description: c.Description,
			Enabled:     disabled.IsItemEnabled(c.ID),
			Detail:      detail,
		})
	}
	return out
}

// RunChecks drives the standard injection loop for a rule: it builds the sender and
// (unless opted out) the OAST helper, then for every parameter of every request runs
// each enabled check's probe. Finding-reporting goes through the probe's File helper.
func RunChecks(
	ctx context.Context,
	t activescan.Target,
	cfg activescan.Config,
	deps activescan.RuleDeps,
	rep activescan.Reporter,
	checks []Check,
	disabled *activescan.DisabledSet,
	findingRule string,
	category detect.Category,
	name string,
) {
	send := Sender(deps, t)
	oast := OAST(deps)
	if cfg.NoOAST {
		oast = nil
	}
	enabled := make([]Check, 0, len(checks))
	for _, c := range checks {
		if disabled.IsItemEnabled(c.ID) {
			enabled = append(enabled, c)
		}
	}
	inject.Drive(ctx, Requests(t), send, rep.Progress, func(ctx context.Context, p inject.Point, base *inject.Baseline) {
		for _, c := range enabled {
			if ctx.Err() != nil {
				return
			}
			file := func(sev detect.Severity, detail, evidence, url string) {
				rep.Finding(Finding(findingRule, category, sev, name, t.Host, base.Method, url, p.Key(), detail, evidence))
			}
			c.Probe(ProbeCtx{Ctx: ctx, Send: send, OAST: oast, Host: t.Host, Point: p, Base: base, File: file})
		}
	})
}
