package team

import (
	"database/sql"
	"time"
)

// ChatMessage represents a team chat message.
type ChatMessage struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Text      string    `json:"text"`
	RefID     string    `json:"refId,omitempty"` // optional flagged-request reference
	CreatedAt time.Time `json:"createdAt"`
}

// FlaggedSummary is a flagged request without its raw bytes (list view).
type FlaggedSummary struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	Truncated bool      `json:"truncated"`
	Note      string    `json:"note"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"createdAt"`
}

// FlaggedRequest is a flagged request including its raw request/response bytes.
type FlaggedRequest struct {
	FlaggedSummary
	ReqRaw  []byte `json:"-"`
	RespRaw []byte `json:"-"`
}

// Note represents a shared team note.
type Note struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Content   string    `json:"content"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Store provides CRUD operations for team chat and notes.
type Store struct {
	db *sql.DB
}

// NewStore creates a new Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreateMessage inserts a new chat message. refID is optional (pass "" for a
// plain message); when set it references a flagged request.
func (s *Store) CreateMessage(id, author, text, refID string) (*ChatMessage, error) {
	now := time.Now().UTC()
	var ref any
	if refID != "" {
		ref = refID
	}
	_, err := s.db.Exec(
		"INSERT INTO team_chat (id, author, text, ref_id, created_at) VALUES (?, ?, ?, ?, ?)",
		id, author, text, ref, now,
	)
	if err != nil {
		return nil, err
	}
	return &ChatMessage{ID: id, Author: author, Text: text, RefID: refID, CreatedAt: now}, nil
}

// ListMessages returns chat messages, paginated, newest first.
func (s *Store) ListMessages(offset, limit int) ([]ChatMessage, int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM team_chat").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		"SELECT id, author, text, ref_id, created_at FROM team_chat ORDER BY created_at DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []ChatMessage
	for rows.Next() {
		var m ChatMessage
		var refID sql.NullString
		if err := rows.Scan(&m.ID, &m.Author, &m.Text, &refID, &m.CreatedAt); err != nil {
			return nil, 0, err
		}
		m.RefID = refID.String
		items = append(items, m)
	}
	return items, total, rows.Err()
}

// CreateNote inserts a new team note.
func (s *Store) CreateNote(id, host, content, author string) (*Note, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		"INSERT INTO team_notes (id, host, content, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, host, content, author, now, now,
	)
	if err != nil {
		return nil, err
	}
	return &Note{ID: id, Host: host, Content: content, Author: author, CreatedAt: now, UpdatedAt: now}, nil
}

// ListNotes returns team notes for a host, paginated.
func (s *Store) ListNotes(host string, offset, limit int) ([]Note, int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM team_notes WHERE host = ?", host).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		"SELECT id, host, content, author, created_at, updated_at FROM team_notes WHERE host = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
		host, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.Host, &n.Content, &n.Author, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, 0, err
		}
		items = append(items, n)
	}
	return items, total, rows.Err()
}

// DeleteNote deletes a team note by ID.
func (s *Store) DeleteNote(id string) error {
	res, err := s.db.Exec("DELETE FROM team_notes WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RecordConnection inserts a connection log entry for a user.
func (s *Store) RecordConnection(nickname, ip string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		"INSERT INTO team_connections (nickname, ip, connected_at) VALUES (?, ?, ?)",
		nickname, ip, now,
	)
	return err
}

// CreateFlagged inserts a new flagged request artifact.
func (s *Store) CreateFlagged(id, host, method, url string, status int, reqRaw, respRaw []byte, truncated bool, note, author string) (*FlaggedRequest, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		"INSERT INTO team_flagged_requests (id, host, method, url, status, req_raw, resp_raw, truncated, note, author, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		id, host, method, url, status, reqRaw, respRaw, truncated, note, author, now,
	)
	if err != nil {
		return nil, err
	}
	return &FlaggedRequest{
		FlaggedSummary: FlaggedSummary{
			ID: id, Host: host, Method: method, URL: url, Status: status,
			Truncated: truncated, Note: note, Author: author, CreatedAt: now,
		},
		ReqRaw:  reqRaw,
		RespRaw: respRaw,
	}, nil
}

// ListFlagged returns flagged request summaries (no raw bytes), paginated, newest first.
func (s *Store) ListFlagged(offset, limit int) ([]FlaggedSummary, int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM team_flagged_requests").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		"SELECT id, host, method, url, status, truncated, note, author, created_at FROM team_flagged_requests ORDER BY created_at DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []FlaggedSummary
	for rows.Next() {
		var f FlaggedSummary
		if err := rows.Scan(&f.ID, &f.Host, &f.Method, &f.URL, &f.Status, &f.Truncated, &f.Note, &f.Author, &f.CreatedAt); err != nil {
			return nil, 0, err
		}
		items = append(items, f)
	}
	return items, total, rows.Err()
}

// GetFlagged returns a single flagged request including raw bytes.
func (s *Store) GetFlagged(id string) (*FlaggedRequest, error) {
	var f FlaggedRequest
	err := s.db.QueryRow(
		"SELECT id, host, method, url, status, req_raw, resp_raw, truncated, note, author, created_at FROM team_flagged_requests WHERE id = ?",
		id,
	).Scan(&f.ID, &f.Host, &f.Method, &f.URL, &f.Status, &f.ReqRaw, &f.RespRaw, &f.Truncated, &f.Note, &f.Author, &f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// DeleteFlagged deletes a flagged request by ID.
func (s *Store) DeleteFlagged(id string) error {
	res, err := s.db.Exec("DELETE FROM team_flagged_requests WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListHosts returns all distinct hosts that have team notes.
func (s *Store) ListHosts() ([]string, error) {
	rows, err := s.db.Query("SELECT DISTINCT host FROM team_notes ORDER BY host")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}
