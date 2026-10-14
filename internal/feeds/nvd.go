package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0).
//
// The unauthenticated rate limit is 5 requests / 30s, so nvdCollect makes just two requests
// per refresh — one for CRITICAL, one for HIGH — over a 24-hour publication window, paced 6s
// apart. The window is wider than the 15-minute refresh so the ticker has depth and a missed
// tick self-heals; the aggregator's rolling cache dedups by CVE id. The API buckets only by
// severity, so the 7.5 floor is applied here.

// nvdCollect fetches recent high-severity CVEs and parses them into normalized items.
func nvdCollect(ctx context.Context, fetch FetchFunc) ([]Item, error) {
	end := time.Now().UTC()
	start := end.Add(-24 * time.Hour)

	var items []Item
	var firstErr error
	for i, sev := range []string{"CRITICAL", "HIGH"} {
		if i > 0 {
			select {
			case <-ctx.Done():
				return items, ctx.Err()
			case <-time.After(6 * time.Second): // stay well under 5 req / 30s
			}
		}
		got, err := nvdFetchSeverity(ctx, fetch, sev, start, end)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		items = append(items, got...)
	}
	// Only surface an error when nothing came back at all; a partial result (one severity
	// succeeded) is better than blanking the category.
	if len(items) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return items, nil
}

func nvdFetchSeverity(ctx context.Context, fetch FetchFunc, severity string, start, end time.Time) ([]Item, error) {
	const nvdTimeLayout = "2006-01-02T15:04:05.000"
	q := url.Values{}
	q.Set("cvssV3Severity", severity)
	q.Set("pubStartDate", start.Format(nvdTimeLayout))
	q.Set("pubEndDate", end.Format(nvdTimeLayout))
	q.Set("resultsPerPage", "2000") // a day of high-sev CVEs fits in one page
	raw, err := fetch(ctx, nvdBaseURL+"?"+q.Encode(), nvdLimit)
	if err != nil {
		return nil, err
	}
	return parseNVD(raw)
}

type nvdResponse struct {
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	Descriptions   []nvdLangString `json:"descriptions"`
	Metrics        nvdMetrics      `json:"metrics"`
	Configurations []nvdConfig     `json:"configurations"`
	Affected       []nvdAffected   `json:"affected"`
}

type nvdLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdCVSSMetric `json:"cvssMetricV31"`
	V30 []nvdCVSSMetric `json:"cvssMetricV30"`
	V2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	Type     string `json:"type"` // "Primary" | "Secondary"
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"` // absent on v2
	} `json:"cvssData"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Criteria string `json:"criteria"`
}

// nvdAffected is the CNA-provided affected-products block NVD 2.0 carries even before it
// runs its own CPE analysis — the real affected vendor/product for a freshly published CVE.
type nvdAffected struct {
	AffectedData []nvdAffectedData `json:"affectedData"`
}

type nvdAffectedData struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// parseNVD normalizes an NVD response, keeping only CVEs scoring >= 7.5.
func parseNVD(raw []byte) ([]Item, error) {
	var resp nvdResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parsing NVD response: %w", err)
	}
	items := make([]Item, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		id, ok := cleanCVEID(v.CVE.ID)
		if !ok {
			continue
		}
		score, severity, ok := nvdScore(v.CVE.Metrics)
		if !ok || score < 7.5 {
			continue
		}
		vendor, product := nvdVendorProduct(v.CVE)
		items = append(items, Item{
			Category:  CategoryCVE,
			ID:        id,
			Title:     sanitizeText(nvdDescription(v.CVE.Descriptions), maxTitle),
			Vendor:    sanitizeText(vendor, maxVendor),
			Product:   sanitizeText(product, maxProduct),
			Severity:  severity,
			Score:     score,
			URL:       nvdCanonicalURL(id),
			Published: normalizeTime(parseNVDTime(v.CVE.Published)),
		})
	}
	return items, nil
}

// nvdScore picks the base score and severity, preferring CVSS v3.1, then v3.0, then v2. A v2
// metric has no severity bucket, so it is derived from the score.
func nvdScore(m nvdMetrics) (float64, string, bool) {
	if s, sev, ok := pickCVSS(m.V31); ok {
		return s, sev, true
	}
	if s, sev, ok := pickCVSS(m.V30); ok {
		return s, sev, true
	}
	for _, e := range m.V2 {
		sc := clampScore(e.CVSSData.BaseScore)
		return sc, deriveSeverity(sc), true
	}
	return 0, "", false
}

func pickCVSS(metrics []nvdCVSSMetric) (float64, string, bool) {
	if len(metrics) == 0 {
		return 0, "", false
	}
	chosen := metrics[0]
	for _, e := range metrics {
		if strings.EqualFold(e.Type, "Primary") {
			chosen = e
			break
		}
	}
	score := clampScore(chosen.CVSSData.BaseScore)
	sev := cleanSeverity(chosen.CVSSData.BaseSeverity)
	if sev == "" {
		sev = deriveSeverity(score)
	}
	return score, sev, true
}

// nvdVendorProduct reads the affected vendor/product, preferring NVD's analyzed CPE and
// falling back to the CNA-provided affected-products block.
//
// CPE first: it is NVD-normalized (so the vendor/product align with the CPE strings Target
// Exposure correlates against) but a freshly published CVE — the ticker's 24h window — usually
// has none yet. For those, `cve.affected[].affectedData[]` carries the real affected vendor
// (e.g. "printcart"), which NVD includes in the same response, so no extra request is needed.
// This is the affected vendor, not the CNA that assigned the CVE (that would be "wordfence" /
// "vulncheck" — wrong). "" (shown as no vendor) only when a CVE has neither, which is rare.
func nvdVendorProduct(c nvdCVE) (string, string) {
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if v, p, ok := cpeVendorProduct(m.Criteria); ok {
					return v, p
				}
			}
		}
	}
	for _, a := range c.Affected {
		for _, ad := range a.AffectedData {
			if v := strings.TrimSpace(ad.Vendor); v != "" && !strings.EqualFold(v, "n/a") {
				return v, strings.TrimSpace(ad.Product)
			}
		}
	}
	return "", ""
}

// cpeVendorProduct parses the vendor and product out of a CPE 2.3 formatted string
// (cpe:2.3:a:vendor:product:version:...). Returns ok=false for anything not in that shape.
func cpeVendorProduct(criteria string) (vendor, product string, ok bool) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", "", false
	}
	vendor = cpeField(parts[3])
	product = cpeField(parts[4])
	if vendor == "" {
		return "", "", false
	}
	return vendor, product, true
}

// cpeField decodes one CPE 2.3 field: "*"/"-" mean unset, "_" separates words, "\" escapes.
func cpeField(f string) string {
	if f == "" || f == "*" || f == "-" {
		return ""
	}
	f = strings.ReplaceAll(f, `\`, "")
	return strings.ReplaceAll(f, "_", " ")
}

func nvdDescription(ds []nvdLangString) string {
	for _, d := range ds {
		if strings.EqualFold(d.Lang, "en") {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}
