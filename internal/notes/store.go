package notes

import (
	"database/sql"
	"time"
)

// Note represents a per-host operator note.
type Note struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Content   string    `json:"content"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Store provides CRUD operations for notes.
type Store struct {
	db *sql.DB
}

// NewStore creates a new Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreateNote inserts a new note.
func (s *Store) CreateNote(id, host, content, author string) (*Note, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		"INSERT INTO notes (id, host, content, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, host, content, author, now, now,
	)
	if err != nil {
		return nil, err
	}
	return &Note{ID: id, Host: host, Content: content, Author: author, CreatedAt: now, UpdatedAt: now}, nil
}

// ListNotes returns notes for a host, paginated.
func (s *Store) ListNotes(host string, offset, limit int) ([]Note, int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM notes WHERE host = ?", host).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		"SELECT id, host, content, author, created_at, updated_at FROM notes WHERE host = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
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

// DeleteNote deletes a note by ID.
func (s *Store) DeleteNote(id string) error {
	res, err := s.db.Exec("DELETE FROM notes WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ClearAll deletes all notes from the store.
func (s *Store) ClearAll() error {
	_, err := s.db.Exec("DELETE FROM notes")
	return err
}

// LoadAll returns every note in the store (used for serialising into project configs).
func (s *Store) LoadAll() ([]Note, error) {
	rows, err := s.db.Query(
		"SELECT id, host, content, author, created_at, updated_at FROM notes ORDER BY host, created_at",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.Host, &n.Content, &n.Author, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, n)
	}
	return items, rows.Err()
}

// ListHosts returns all distinct hosts that have notes.
func (s *Store) ListHosts() ([]string, error) {
	rows, err := s.db.Query("SELECT DISTINCT host FROM notes ORDER BY host")
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
