package feeds

import "context"

// The curated source registry. Feed URLs are compile-time constants, the same way the
// updater pins its GitHub destination: no operator-supplied URL ever reaches the fetcher, so
// this feature is not an arbitrary-outbound-on-a-timer primitive and needs no SSRF/private-IP
// egress guard (there is none in the codebase to borrow). Adding a headline source means
// adding a vetted host to its allow-list here — never a field the operator can set.
const (
	nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdLimit   = 8 << 20

	kevURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevLimit = 8 << 20 // the KEV file is ~2 MB and grows; far above the updater's 1 MB

	rssLimit = 2 << 20
)

// Source is one feed. collect encapsulates how it is fetched and parsed (NVD needs two
// requests; KEV and RSS one), so the aggregator treats every source uniformly.
type Source struct {
	ID       string
	Name     string
	Category Category
	collect  func(ctx context.Context, fetch FetchFunc) ([]Item, error)
}

// DefaultSources is the built-in feed set.
func DefaultSources() []Source {
	return []Source{
		{
			ID:       "nvd-cve",
			Name:     "NVD",
			Category: CategoryCVE,
			collect:  nvdCollect,
		},
		{
			ID:       "cisa-kev",
			Name:     "CISA KEV",
			Category: CategoryKEV,
			collect: func(ctx context.Context, fetch FetchFunc) ([]Item, error) {
				raw, err := fetch(ctx, kevURL, kevLimit)
				if err != nil {
					return nil, err
				}
				return parseKEV(raw)
			},
		},
		rssSource("cisa-advisories", "CISA Advisories", CategoryHeadline,
			"https://www.cisa.gov/cybersecurity-advisories/all.xml",
			[]string{"cisa.gov"}),
		// The us-cert.cisa.gov/ncas/analysis-reports.xml form 301-redirects here; feedsFetch
		// does not follow redirects, so the resolved URL is pinned directly.
		rssSource("cisa-analysis-reports", "CISA Analysis Reports", CategoryHeadline,
			"https://www.cisa.gov/cybersecurity-advisories/analysis-reports.xml",
			[]string{"cisa.gov"}),
		rssSource("bishopfox-blog", "Bishop Fox Blog", CategoryHeadline,
			"https://bishopfox.com/feeds/blog.rss",
			[]string{"bishopfox.com"}),
		rssSource("cert-cc", "CERT/CC", CategoryHeadline,
			"https://www.kb.cert.org/vulfeed/",
			[]string{"kb.cert.org"}),
	}
}

func rssSource(id, name string, category Category, feedURL string, allowHosts []string) Source {
	return Source{
		ID:       id,
		Name:     name,
		Category: category,
		collect: func(ctx context.Context, fetch FetchFunc) ([]Item, error) {
			raw, err := fetch(ctx, feedURL, rssLimit)
			if err != nil {
				return nil, err
			}
			return parseFeed(raw, name, allowHosts)
		},
	}
}
