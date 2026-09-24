package anomaly

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/detect"
)

// Signal rule IDs. Each is a stable synthetic RuleID so a finding's identity
// (FindingID(ruleID, host, endpointKey)) is deterministic and dedups across
// cycles. They are not engine rules; handleGetFinding returns rule:null for
// them and the UI reads Detail instead.
const (
	ruleShape     = "anomaly.shape"
	ruleSize      = "anomaly.size"
	ruleLatency   = "anomaly.latency"
	ruleStructure = "anomaly.structure"
	ruleHeader    = "anomaly.header"
)

var ruleNames = map[string]string{
	ruleShape:     "Response-shape outlier",
	ruleSize:      "Response-size outlier",
	ruleLatency:   "Latency outlier",
	ruleStructure: "Structural outlier",
	ruleHeader:    "Header / tech outlier",
}

// thresholds tune how stark an outlier must be to report. Sensitivity selects a
// set; see thresholdsFor.
type thresholds struct {
	minEndpoints int     // host needs at least this many endpoints for any signal
	minMetric    int     // endpoints with a numeric metric before size/latency run
	rareFrac     float64 // a category on fewer than this fraction of endpoints is rare
	dominateFrac float64 // the modal category must cover at least this to call others out
	zThresh      float64 // robust-z magnitude to flag a size/latency outlier
}

func thresholdsFor(sens string) thresholds {
	switch sens {
	case "low":
		return thresholds{minEndpoints: 12, minMetric: 12, rareFrac: 0.05, dominateFrac: 0.75, zThresh: 4.5}
	case "high":
		return thresholds{minEndpoints: 5, minMetric: 6, rareFrac: 0.15, dominateFrac: 0.55, zThresh: 3.0}
	default: // medium
		return thresholds{minEndpoints: 8, minMetric: 8, rareFrac: 0.10, dominateFrac: 0.65, zThresh: 3.5}
	}
}

// endpoint aggregates the records that share one host+method+templated-path.
type endpoint struct {
	key      string // "METHOD /norm/path" — the finding's group dimension
	host     string
	method   string
	norm     string
	n        int
	repTS    int64
	repReqID string
	repURL   string
	repMeth  string

	ctCount     map[string]int
	statusCount map[int]int
	sizes       []float64
	durs        []float64
	params      map[string]struct{}
	ext         string
	techCount   map[string]int
	authCount   map[string]int
}

func (ep *endpoint) add(r *record) {
	ep.n++
	if r.ts >= ep.repTS {
		ep.repTS = r.ts
		ep.repReqID = r.reqID
		ep.repURL = r.url
		ep.repMeth = r.method
	}
	if r.majorCT != "" {
		ep.ctCount[r.majorCT]++
	}
	if r.statusClass != 0 {
		ep.statusCount[r.statusClass]++
	}
	ep.sizes = append(ep.sizes, float64(r.size))
	if r.hasDur {
		ep.durs = append(ep.durs, float64(r.durMs))
	}
	for _, p := range r.params {
		ep.params[p] = struct{}{}
	}
	if r.ext != "" {
		ep.ext = r.ext
	}
	if r.tech != "" {
		ep.techCount[r.tech]++
	}
	if r.authScheme != "" {
		ep.authCount[r.authScheme]++
	}
}

func (ep *endpoint) modalCT() string     { s, _ := modalStr(ep.ctCount); return s }
func (ep *endpoint) modalStatus() int    { s, _ := modalInt(ep.statusCount); return s }
func (ep *endpoint) modalTech() string   { s, _ := modalStr(ep.techCount); return s }
func (ep *endpoint) modalAuth() string   { s, _ := modalStr(ep.authCount); return s }
func (ep *endpoint) medianSize() float64 { return median(ep.sizes) }
func (ep *endpoint) medianDur() float64  { return median(ep.durs) }

// analyzeHost groups a host's records into endpoints and runs every signal,
// returning the anomaly findings for that host. Below the endpoint floor it
// returns nothing: with too few endpoints, everything looks like an outlier.
func analyzeHost(host string, recs []*record, th thresholds) []detect.Finding {
	byKey := map[string]*endpoint{}
	for _, r := range recs {
		key := r.method + " " + r.norm
		ep := byKey[key]
		if ep == nil {
			ep = &endpoint{
				key: key, host: host, method: r.method, norm: r.norm,
				ctCount: map[string]int{}, statusCount: map[int]int{},
				params: map[string]struct{}{}, techCount: map[string]int{},
				authCount: map[string]int{},
			}
			byKey[key] = ep
		}
		ep.add(r)
	}

	eps := make([]*endpoint, 0, len(byKey))
	for _, ep := range byKey {
		eps = append(eps, ep)
	}
	if len(eps) < th.minEndpoints {
		return nil
	}
	// Deterministic order so findings emit stably.
	sort.Slice(eps, func(i, j int) bool { return eps[i].key < eps[j].key })

	// reasons accumulates one detail string per (ruleID, endpoint) so, e.g., a
	// shape outlier tripping on both content-type and status is one finding.
	type fkey struct {
		rule string
		ep   *endpoint
	}
	reasons := map[fkey][]string{}
	strong := map[fkey]bool{}
	add := func(rule string, ep *endpoint, isStrong bool, msg string) {
		k := fkey{rule, ep}
		reasons[k] = append(reasons[k], msg)
		if isStrong {
			strong[k] = true
		}
	}

	shapeSignal(eps, th, func(ep *endpoint, s bool, msg string) { add(ruleShape, ep, s, msg) })
	sizeSignal(eps, th, func(ep *endpoint, s bool, msg string) { add(ruleSize, ep, s, msg) })
	latencySignal(eps, th, func(ep *endpoint, s bool, msg string) { add(ruleLatency, ep, s, msg) })
	structureSignal(eps, th, func(ep *endpoint, s bool, msg string) { add(ruleStructure, ep, s, msg) })
	headerSignal(eps, th, func(ep *endpoint, s bool, msg string) { add(ruleHeader, ep, s, msg) })

	out := make([]detect.Finding, 0, len(reasons))
	for k, msgs := range reasons {
		sev := detect.SeverityInfo
		conf := detect.ConfidenceLow
		if strong[k] {
			sev = detect.SeverityLow
			conf = detect.ConfidenceMedium
		}
		out = append(out, k.ep.finding(k.rule, strings.Join(msgs, "; "), sev, conf))
	}
	return out
}

// shapeSignal flags an endpoint whose modal content-type or status class differs
// from a host that is otherwise dominated by one value.
func shapeSignal(eps []*endpoint, th thresholds, emit func(*endpoint, bool, string)) {
	n := len(eps)
	ctFreq := map[string]int{}
	stFreq := map[int]int{}
	for _, ep := range eps {
		if ct := ep.modalCT(); ct != "" {
			ctFreq[ct]++
		}
		if st := ep.modalStatus(); st != 0 {
			stFreq[st]++
		}
	}
	domCT, domCTn := modalStr(ctFreq)
	domST, domSTn := modalInt(stFreq)
	ctDominates := domCT != "" && float64(domCTn)/float64(n) >= th.dominateFrac
	stDominates := domST != 0 && float64(domSTn)/float64(n) >= th.dominateFrac

	for _, ep := range eps {
		ct := ep.modalCT()
		if ctDominates && ct != "" && ct != domCT && frac(ctFreq[ct], n) < th.rareFrac {
			strong := ctFreq[ct] == 1
			emit(ep, strong, fmt.Sprintf("content-type %s; host is mostly %s (%d/%d endpoints)", ct, domCT, ctFreq[ct], n))
		}
		st := ep.modalStatus()
		if stDominates && st != 0 && st != domST && frac(stFreq[st], n) < th.rareFrac {
			strong := stFreq[st] == 1
			emit(ep, strong, fmt.Sprintf("status %dxx; host is mostly %dxx (%d/%d endpoints)", st, domST, stFreq[st], n))
		}
	}
}

// sizeSignal flags an endpoint whose median response size is a robust-z outlier
// among the host's per-endpoint medians.
func sizeSignal(eps []*endpoint, th thresholds, emit func(*endpoint, bool, string)) {
	var meds []float64
	var have []*endpoint
	for _, ep := range eps {
		if len(ep.sizes) == 0 {
			continue
		}
		meds = append(meds, ep.medianSize())
		have = append(have, ep)
	}
	if len(have) < th.minMetric {
		return
	}
	med := median(meds)
	spread := mad(meds, med)
	for i, ep := range have {
		z := robustZ(meds[i], med, spread)
		if z >= th.zThresh {
			emit(ep, z >= th.zThresh*1.7, fmt.Sprintf("response size %s bytes; host median %s (z=%.1f)",
				commas(int64(meds[i])), commas(int64(med)), z))
		}
	}
}

// latencySignal is sizeSignal for response duration.
func latencySignal(eps []*endpoint, th thresholds, emit func(*endpoint, bool, string)) {
	var meds []float64
	var have []*endpoint
	for _, ep := range eps {
		if len(ep.durs) == 0 {
			continue
		}
		meds = append(meds, ep.medianDur())
		have = append(have, ep)
	}
	if len(have) < th.minMetric {
		return
	}
	med := median(meds)
	spread := mad(meds, med)
	for i, ep := range have {
		z := robustZ(meds[i], med, spread)
		// Only slow outliers are interesting; a fast endpoint is not a lead.
		if z >= th.zThresh && meds[i] > med {
			emit(ep, z >= th.zThresh*1.7, fmt.Sprintf("median latency %dms; host median %dms (z=%.1f)",
				int64(meds[i]), int64(med), z))
		}
	}
}

// structureSignal flags a rare non-asset extension or a parameter name unique to
// one endpoint on the host.
func structureSignal(eps []*endpoint, _ thresholds, emit func(*endpoint, bool, string)) {
	extFreq := map[string]int{}
	paramFreq := map[string]int{}
	for _, ep := range eps {
		if ep.ext != "" {
			extFreq[ep.ext]++
		}
		for p := range ep.params {
			paramFreq[p]++
		}
	}
	for _, ep := range eps {
		if ep.ext != "" {
			_, common := commonWebExt[ep.ext]
			if !common && extFreq[ep.ext] == 1 {
				emit(ep, true, fmt.Sprintf("extension .%s appears on no other endpoint", ep.ext))
			}
		}
		var uniq []string
		for p := range ep.params {
			if paramFreq[p] == 1 {
				uniq = append(uniq, p)
			}
		}
		if len(uniq) > 0 {
			sort.Strings(uniq)
			emit(ep, false, fmt.Sprintf("parameter(s) %s used by no other endpoint", strings.Join(uniq, ", ")))
		}
	}
}

// headerSignal flags an endpoint exposing a framework/server token or auth scheme
// rare for the host.
func headerSignal(eps []*endpoint, th thresholds, emit func(*endpoint, bool, string)) {
	n := len(eps)
	techFreq := map[string]int{}
	authFreq := map[string]int{}
	for _, ep := range eps {
		if t := ep.modalTech(); t != "" {
			techFreq[t]++
		}
		if a := ep.modalAuth(); a != "" {
			authFreq[a]++
		}
	}
	domTech, domTechN := modalStr(techFreq)
	techDominates := domTech != "" && float64(domTechN)/float64(n) >= th.dominateFrac
	for _, ep := range eps {
		t := ep.modalTech()
		if techDominates && t != "" && t != domTech && frac(techFreq[t], n) < th.rareFrac {
			emit(ep, techFreq[t] == 1, fmt.Sprintf("tech %q; rest of host is %q (%d/%d)", t, domTech, techFreq[t], n))
		}
		a := ep.modalAuth()
		if a != "" && frac(authFreq[a], n) < th.rareFrac {
			emit(ep, authFreq[a] == 1, fmt.Sprintf("auth scheme %q is rare on this host (%d/%d)", a, authFreq[a], n))
		}
	}
}

// finding assembles a detect.Finding pointing at the endpoint's most recent
// capture, so the operator's row actions (Send to Fuzz, Copy as curl) work. It
// carries no occurrences: the representative moves each cycle and an occurrence
// per move would inflate Count without meaning.
func (ep *endpoint) finding(ruleID, detail string, sev detect.Severity, conf detect.Confidence) detect.Finding {
	now := time.Now()
	return detect.Finding{
		ID:             detect.FindingID(ruleID, ep.host, ep.key),
		RuleID:         ruleID,
		RuleName:       ruleNames[ruleID],
		Category:       detect.CategoryAnomaly,
		Severity:       sev,
		Confidence:     conf,
		Target:         detect.TargetMessage,
		Host:           ep.host,
		Method:         ep.repMeth,
		URL:            ep.repURL,
		RequestID:      ep.repReqID,
		Detail:         ep.key,
		Evidence:       detail,
		EvidenceOffset: -1,
		FirstSeen:      now,
		LastSeen:       now,
	}
}

func frac(count, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) / float64(total)
}

// commas formats an integer with thousands separators for readable evidence.
func commas(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
