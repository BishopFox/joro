package feeds

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// Headline feeds, RSS 2.0 / RSS 1.0 / Atom. Only the title, link, and date are read — never
// a <description>/<content>/<summary> body, which is where a feed's HTML lives. The link is
// the one value that cannot be derived, so it runs through validateURL against the source's
// host allow-list; a link that fails validation yields an item with an empty URL (shown as
// plain text, no anchor) rather than being dropped.
//
// encoding/xml does not fetch external entities or process DTDs, so XXE is not reachable;
// Entity is pinned to the known HTML named-entity set and the input is already bounded by the
// fetch LimitReader, which is what actually caps any entity expansion.

type feedKind int

const (
	feedUnknown feedKind = iota
	feedRSS
	feedAtom
)

type rssFeed struct {
	Channel struct {
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
	// RSS 1.0 (RDF) places items as siblings of channel, not inside it.
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title   string `xml:"title"`
	Link    string `xml:"link"`
	PubDate string `xml:"pubDate"`
	Date    string `xml:"date"` // dc:date (RSS 1.0)
}

type atomFeed struct {
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title     string     `xml:"title"`
	Links     []atomLink `xml:"link"`
	Updated   string     `xml:"updated"`
	Published string     `xml:"published"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

// parseFeed sniffs the root element and dispatches to the RSS or Atom parser.
func parseFeed(raw []byte, sourceName string, allowHosts []string) ([]Item, error) {
	switch sniffFeed(raw) {
	case feedAtom:
		return parseAtom(raw, sourceName, allowHosts)
	case feedRSS:
		return parseRSS(raw, sourceName, allowHosts)
	default:
		return nil, fmt.Errorf("unrecognized feed format for %q", sourceName)
	}
}

func newXMLDecoder(raw []byte) *xml.Decoder {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false          // real-world feeds are not always well-formed
	dec.Entity = xml.HTMLEntity // known named entities only; no custom general-entity expansion
	return dec
}

func sniffFeed(raw []byte) feedKind {
	dec := newXMLDecoder(raw)
	for {
		tok, err := dec.Token()
		if err != nil {
			return feedUnknown
		}
		if se, ok := tok.(xml.StartElement); ok {
			switch strings.ToLower(se.Name.Local) {
			case "feed":
				return feedAtom
			case "rss", "rdf":
				return feedRSS
			default:
				return feedUnknown
			}
		}
	}
}

func parseRSS(raw []byte, sourceName string, allowHosts []string) ([]Item, error) {
	var feed rssFeed
	if err := newXMLDecoder(raw).Decode(&feed); err != nil {
		return nil, fmt.Errorf("parsing RSS for %q: %w", sourceName, err)
	}
	all := append(feed.Channel.Items, feed.Items...)
	items := make([]Item, 0, len(all))
	for _, it := range all {
		items = append(items, headlineItem(sourceName, it.Title, it.Link, firstNonEmpty(it.PubDate, it.Date), allowHosts))
	}
	return items, nil
}

func parseAtom(raw []byte, sourceName string, allowHosts []string) ([]Item, error) {
	var feed atomFeed
	if err := newXMLDecoder(raw).Decode(&feed); err != nil {
		return nil, fmt.Errorf("parsing Atom for %q: %w", sourceName, err)
	}
	items := make([]Item, 0, len(feed.Entries))
	for _, e := range feed.Entries {
		link := atomPrimaryLink(e.Links)
		items = append(items, headlineItem(sourceName, e.Title, link, firstNonEmpty(e.Published, e.Updated), allowHosts))
	}
	return items, nil
}

// atomPrimaryLink picks the article link: rel="alternate", else the first rel-less link.
func atomPrimaryLink(links []atomLink) string {
	for _, l := range links {
		if strings.EqualFold(l.Rel, "alternate") {
			return l.Href
		}
	}
	for _, l := range links {
		if l.Rel == "" {
			return l.Href
		}
	}
	if len(links) > 0 {
		return links[0].Href
	}
	return ""
}

func headlineItem(sourceName, title, link, dateStr string, allowHosts []string) Item {
	cleanLink, _ := validateURL(link, allowHosts)
	return Item{
		Category:  CategoryHeadline,
		ID:        headlineID(sourceName, link),
		Title:     sanitizeText(title, maxTitle),
		URL:       cleanLink,
		Source:    sanitizeText(sourceName, maxSource),
		Published: normalizeTime(parseFeedTime(dateStr)),
	}
}
