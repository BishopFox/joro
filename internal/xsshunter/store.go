package xsshunter

import (
	"database/sql"
	"time"
)

// Probe represents an XSS probe that generates callback payloads.
type Probe struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ProbeID      string    `json:"probeId"`
	CollectPages string    `json:"collectPages"`
	ChainloadURI string    `json:"chainloadUri"`
	CreatedAt    time.Time `json:"createdAt"`
	FireCount    int       `json:"fireCount"`
}

// Fire represents a captured XSS payload execution.
type Fire struct {
	ID           string    `json:"id"`
	ProbeID      string    `json:"probeId"`
	ProbeToken   string    `json:"probeToken"`
	URL          string    `json:"url"`
	Origin       string    `json:"origin"`
	Referrer     string    `json:"referrer"`
	UserAgent    string    `json:"userAgent"`
	Cookies      string    `json:"cookies"`
	PageTitle    string    `json:"pageTitle"`
	DOM          string    `json:"dom,omitempty"`
	Screenshot   string    `json:"screenshot,omitempty"`
	PageText     string    `json:"pageText,omitempty"`
	SourceIP     string    `json:"sourceIp"`
	InIframe     bool      `json:"inIframe"`
	BrowserTime  string    `json:"browserTime"`
	InjectionKey string    `json:"injectionKey,omitempty"`
	FiredAt      time.Time `json:"firedAt"`
}

// FireSummary is a Fire without DOM, Screenshot, and PageText for list responses.
type FireSummary struct {
	ID           string    `json:"id"`
	ProbeID      string    `json:"probeId"`
	ProbeToken   string    `json:"probeToken"`
	URL          string    `json:"url"`
	Origin       string    `json:"origin"`
	Referrer     string    `json:"referrer"`
	UserAgent    string    `json:"userAgent"`
	Cookies      string    `json:"cookies"`
	PageTitle    string    `json:"pageTitle"`
	SourceIP     string    `json:"sourceIp"`
	InIframe     bool      `json:"inIframe"`
	BrowserTime  string    `json:"browserTime"`
	InjectionKey string    `json:"injectionKey,omitempty"`
	FiredAt      time.Time `json:"firedAt"`
}

// CollectedPage represents a page fetched by the probe during an XSS fire.
type CollectedPage struct {
	ID          string    `json:"id"`
	FireID      string    `json:"fireId"`
	URL         string    `json:"url"`
	HTML        string    `json:"html,omitempty"`
	CollectedAt time.Time `json:"collectedAt"`
}

// CollectedPageSummary is a CollectedPage without HTML for list responses.
type CollectedPageSummary struct {
	ID          string    `json:"id"`
	FireID      string    `json:"fireId"`
	URL         string    `json:"url"`
	CollectedAt time.Time `json:"collectedAt"`
}

// Store provides CRUD operations for XSS probes and fires.
type Store struct {
	db *sql.DB
}

// NewStore creates a new Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreateProbe inserts a new probe.
func (s *Store) CreateProbe(id, name, hex string) (*Probe, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		"INSERT INTO xss_probes (id, name, probe_id, created_at) VALUES (?, ?, ?, ?)",
		id, name, hex, now,
	)
	if err != nil {
		return nil, err
	}
	return &Probe{ID: id, Name: name, ProbeID: hex, CreatedAt: now}, nil
}

// ListProbes returns all probes with their fire counts.
func (s *Store) ListProbes() ([]Probe, error) {
	rows, err := s.db.Query(`
		SELECT p.id, p.name, p.probe_id, p.collect_pages, p.chainload_uri,
			p.created_at, COUNT(f.id) as fire_count
		FROM xss_probes p
		LEFT JOIN xss_fires f ON f.probe_id = p.id
		GROUP BY p.id
		ORDER BY p.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var probes []Probe
	for rows.Next() {
		var p Probe
		if err := rows.Scan(&p.ID, &p.Name, &p.ProbeID, &p.CollectPages, &p.ChainloadURI,
			&p.CreatedAt, &p.FireCount); err != nil {
			return nil, err
		}
		probes = append(probes, p)
	}
	return probes, rows.Err()
}

// DeleteProbe deletes a probe and cascades to fires.
func (s *Store) DeleteProbe(id string) error {
	res, err := s.db.Exec("DELETE FROM xss_probes WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// FindProbeByID looks up a probe by its UUID.
func (s *Store) FindProbeByID(id string) (*Probe, error) {
	var p Probe
	err := s.db.QueryRow(
		"SELECT id, name, probe_id, collect_pages, chainload_uri, created_at FROM xss_probes WHERE id = ?", id,
	).Scan(&p.ID, &p.Name, &p.ProbeID, &p.CollectPages, &p.ChainloadURI, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// FindProbeByHex looks up a probe by its hex string.
func (s *Store) FindProbeByHex(hex string) (*Probe, error) {
	var p Probe
	err := s.db.QueryRow(
		"SELECT id, name, probe_id, collect_pages, chainload_uri, created_at FROM xss_probes WHERE probe_id = ?", hex,
	).Scan(&p.ID, &p.Name, &p.ProbeID, &p.CollectPages, &p.ChainloadURI, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateProbe updates the collect_pages and chainload_uri for a probe.
func (s *Store) UpdateProbe(id, collectPages, chainloadURI string) error {
	res, err := s.db.Exec(
		"UPDATE xss_probes SET collect_pages = ?, chainload_uri = ? WHERE id = ?",
		collectPages, chainloadURI, id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RecordFire inserts a new fire.
func (s *Store) RecordFire(f *Fire) error {
	inIframe := 0
	if f.InIframe {
		inIframe = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO xss_fires (id, probe_id, probe_token, url, origin, referrer,
			user_agent, cookies, page_title, dom, screenshot, source_ip,
			in_iframe, browser_time, page_text, injection_key, fired_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.ProbeID, f.ProbeToken, f.URL, f.Origin, f.Referrer,
		f.UserAgent, f.Cookies, f.PageTitle, f.DOM, f.Screenshot, f.SourceIP,
		inIframe, f.BrowserTime, f.PageText, f.InjectionKey, f.FiredAt,
	)
	return err
}

// ListFires returns fires (without DOM/screenshot/pageText), optionally filtered by probe ID.
func (s *Store) ListFires(probeID string, offset, limit int) ([]FireSummary, int, error) {
	var total int
	var args []any

	countQ := "SELECT COUNT(*) FROM xss_fires"
	listQ := `SELECT id, probe_id, probe_token, url, origin, referrer,
		user_agent, cookies, page_title, source_ip, in_iframe, browser_time,
		injection_key, fired_at
		FROM xss_fires`

	if probeID != "" {
		countQ += " WHERE probe_id = ?"
		listQ += " WHERE probe_id = ?"
		args = append(args, probeID)
	}

	if err := s.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQ += " ORDER BY fired_at DESC LIMIT ? OFFSET ?"
	listArgs := append(args, limit, offset)

	rows, err := s.db.Query(listQ, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []FireSummary
	for rows.Next() {
		var f FireSummary
		var inIframe int
		if err := rows.Scan(&f.ID, &f.ProbeID, &f.ProbeToken, &f.URL, &f.Origin, &f.Referrer,
			&f.UserAgent, &f.Cookies, &f.PageTitle, &f.SourceIP, &inIframe, &f.BrowserTime,
			&f.InjectionKey, &f.FiredAt); err != nil {
			return nil, 0, err
		}
		f.InIframe = inIframe != 0
		items = append(items, f)
	}
	return items, total, rows.Err()
}

// GetFire returns a single fire with full data (including DOM and screenshot).
func (s *Store) GetFire(id string) (*Fire, error) {
	var f Fire
	var inIframe int
	err := s.db.QueryRow(`
		SELECT id, probe_id, probe_token, url, origin, referrer,
			user_agent, cookies, page_title, dom, screenshot, source_ip,
			in_iframe, browser_time, page_text, injection_key, fired_at
		FROM xss_fires WHERE id = ?`, id,
	).Scan(&f.ID, &f.ProbeID, &f.ProbeToken, &f.URL, &f.Origin, &f.Referrer,
		&f.UserAgent, &f.Cookies, &f.PageTitle, &f.DOM, &f.Screenshot, &f.SourceIP,
		&inIframe, &f.BrowserTime, &f.PageText, &f.InjectionKey, &f.FiredAt)
	if err != nil {
		return nil, err
	}
	f.InIframe = inIframe != 0
	return &f, nil
}

// DeleteFire deletes a single fire by ID.
func (s *Store) DeleteFire(id string) error {
	res, err := s.db.Exec("DELETE FROM xss_fires WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ClearFires deletes fires, optionally filtered by probe ID.
func (s *Store) ClearFires(probeID string) error {
	if probeID != "" {
		_, err := s.db.Exec("DELETE FROM xss_fires WHERE probe_id = ?", probeID)
		return err
	}
	_, err := s.db.Exec("DELETE FROM xss_fires")
	return err
}

// RecordCollectedPage inserts a collected page.
func (s *Store) RecordCollectedPage(p *CollectedPage) error {
	_, err := s.db.Exec(`
		INSERT INTO xss_collected_pages (id, fire_id, url, html, collected_at)
		VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.FireID, p.URL, p.HTML, p.CollectedAt,
	)
	return err
}

// ListCollectedPages returns collected page summaries (without HTML) for a fire.
func (s *Store) ListCollectedPages(fireID string) ([]CollectedPageSummary, error) {
	rows, err := s.db.Query(
		"SELECT id, fire_id, url, collected_at FROM xss_collected_pages WHERE fire_id = ? ORDER BY collected_at",
		fireID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pages []CollectedPageSummary
	for rows.Next() {
		var p CollectedPageSummary
		if err := rows.Scan(&p.ID, &p.FireID, &p.URL, &p.CollectedAt); err != nil {
			return nil, err
		}
		pages = append(pages, p)
	}
	return pages, rows.Err()
}

// GetCollectedPage returns a collected page with full HTML.
func (s *Store) GetCollectedPage(id string) (*CollectedPage, error) {
	var p CollectedPage
	err := s.db.QueryRow(
		"SELECT id, fire_id, url, html, collected_at FROM xss_collected_pages WHERE id = ?", id,
	).Scan(&p.ID, &p.FireID, &p.URL, &p.HTML, &p.CollectedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// FindRecentFireByProbeHex returns the most recent fire for a probe hex within the last 60 seconds.
func (s *Store) FindRecentFireByProbeHex(probeHex string) (*Fire, error) {
	var f Fire
	var inIframe int
	err := s.db.QueryRow(`
		SELECT id, probe_id, probe_token, url, origin, referrer,
			user_agent, cookies, page_title, source_ip,
			in_iframe, browser_time, injection_key, fired_at
		FROM xss_fires
		WHERE probe_token = ? AND fired_at >= datetime('now', '-60 seconds')
		ORDER BY fired_at DESC LIMIT 1`, probeHex,
	).Scan(&f.ID, &f.ProbeID, &f.ProbeToken, &f.URL, &f.Origin, &f.Referrer,
		&f.UserAgent, &f.Cookies, &f.PageTitle, &f.SourceIP,
		&inIframe, &f.BrowserTime, &f.InjectionKey, &f.FiredAt)
	if err != nil {
		return nil, err
	}
	f.InIframe = inIframe != 0
	return &f, nil
}
