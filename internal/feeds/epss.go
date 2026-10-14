package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"strings"
)

// EPSS (Exploit Prediction Scoring System, FIRST.org): the probability a CVE will be
// exploited in the next 30 days. It joins cleanly onto the CVE and KEV sets by CVE id, so it
// is an enrichment rather than a category — no panel of its own, just a score on existing
// items. One API query per chunk per refresh; a failure leaves items unscored.
//
// The query is built from ids that already passed cleanCVEID, via url.Values, so nothing a
// feed supplied can inject a parameter or path into the request.

const (
	epssBaseURL   = "https://api.first.org/data/v1/epss"
	epssLimit     = 2 << 20
	epssChunkSize = 100
)

type epssResponse struct {
	Data []epssDatum `json:"data"`
}

type epssDatum struct {
	CVE  string `json:"cve"`
	EPSS string `json:"epss"` // a decimal string, e.g. "0.00123"
}

// enrichEPSS fetches EPSS scores for the current CVE + KEV items and sets Item.EPSS.
func (a *Aggregator) enrichEPSS(ctx context.Context) {
	ids := a.epssCandidates()
	if len(ids) == 0 {
		return
	}
	scores := make(map[string]float64, len(ids))
	for _, chunk := range chunkStrings(ids, epssChunkSize) {
		if ctx.Err() != nil {
			return
		}
		m, err := a.fetchEPSS(ctx, chunk)
		if err != nil {
			continue // best effort; keep whatever other chunks returned
		}
		maps.Copy(scores, m)
	}
	if len(scores) > 0 {
		a.applyEPSS(scores)
	}
}

// epssCandidates returns the unique validated CVE ids currently held in the CVE and KEV sets.
func (a *Aggregator) epssCandidates() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	seen := map[string]bool{}
	var ids []string
	for _, cat := range []Category{CategoryCVE, CategoryKEV} {
		for _, it := range a.items[cat] {
			if id, ok := cleanCVEID(it.ID); ok && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func (a *Aggregator) fetchEPSS(ctx context.Context, ids []string) (map[string]float64, error) {
	q := url.Values{}
	q.Set("cve", strings.Join(ids, ","))
	q.Set("pretty", "false")
	raw, err := a.fetch(ctx, epssBaseURL+"?"+q.Encode(), epssLimit)
	if err != nil {
		return nil, err
	}
	var resp epssResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parsing EPSS response: %w", err)
	}
	out := make(map[string]float64, len(resp.Data))
	for _, d := range resp.Data {
		id, ok := cleanCVEID(d.CVE)
		if !ok {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(d.EPSS), 64); err == nil {
			out[id] = clampUnit(v)
		}
	}
	return out, nil
}

// applyEPSS writes scores onto the matching CVE + KEV items in place.
func (a *Aggregator) applyEPSS(scores map[string]float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, cat := range []Category{CategoryCVE, CategoryKEV} {
		list := a.items[cat]
		for i := range list {
			if s, ok := scores[list[i].ID]; ok {
				list[i].EPSS = s
			}
		}
	}
}

func clampUnit(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

func chunkStrings(s []string, n int) [][]string {
	if n <= 0 || len(s) <= n {
		return [][]string{s}
	}
	var out [][]string
	for i := 0; i < len(s); i += n {
		out = append(out, s[i:min(i+n, len(s))])
	}
	return out
}
