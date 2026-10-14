package feeds

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CISA Known Exploited Vulnerabilities catalog: one JSON file, no auth. It is the most
// actionable feed — every entry is a vulnerability being exploited in the wild. The file is
// a couple of megabytes and grows monotonically, which is why its read cap (kevLimit) is far
// above the updater's 1 MB: a truncated file would fail to parse forever.

type kevFile struct {
	Vulnerabilities []kevVuln `json:"vulnerabilities"`
}

type kevVuln struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
}

// parseKEV normalizes the KEV catalog, newest additions first (sorting happens in the
// aggregator). The URL is derived from the cleaned CVE id, never taken from the file.
func parseKEV(raw []byte) ([]Item, error) {
	var f kevFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing KEV catalog: %w", err)
	}
	items := make([]Item, 0, len(f.Vulnerabilities))
	for _, v := range f.Vulnerabilities {
		id, ok := cleanCVEID(v.CVEID)
		if !ok {
			continue
		}
		items = append(items, Item{
			Category:   CategoryKEV,
			ID:         id,
			Title:      sanitizeText(v.VulnerabilityName, maxTitle),
			Summary:    sanitizeText(v.ShortDescription, maxSummary),
			Vendor:     sanitizeText(v.VendorProject, maxVendor),
			Product:    sanitizeText(v.Product, maxProduct),
			Ransomware: strings.EqualFold(strings.TrimSpace(v.KnownRansomware), "Known"),
			URL:        nvdCanonicalURL(id),
			Published:  normalizeTime(parseKEVDate(v.DateAdded)),
		})
	}
	return items, nil
}
