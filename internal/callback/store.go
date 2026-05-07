package callback

import (
	"database/sql"
	"time"
)

// Token represents a callback token.
type Token struct {
	ID        string    `json:"id"`
	Note      string    `json:"note"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"createdAt"`
	HitCount  int       `json:"hitCount"`
}

// Interaction represents a recorded callback interaction (DNS or HTTP).
type Interaction struct {
	ID         string    `json:"id"`
	TokenID    string    `json:"tokenId"`
	Token      string    `json:"token"`
	Type       string    `json:"type"`
	SourceIP   string    `json:"sourceIp"`
	Timestamp  time.Time `json:"timestamp"`
	QueryName  string    `json:"queryName,omitempty"`
	QueryType  string    `json:"queryType,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Headers    string    `json:"headers,omitempty"`
	Body       string    `json:"body,omitempty"`
	RawRequest string    `json:"rawRequest,omitempty"`
	Source     string    `json:"source,omitempty"`
}

// CallbackConfig holds callback server configuration.
type CallbackConfig struct {
	Domain     string `json:"domain"`
	ResponseIP string `json:"responseIp"`
}

// Store provides CRUD operations for tokens and interactions.
type Store struct {
	db *sql.DB
}

// NewStore creates a new Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreateToken inserts a new token.
func (s *Store) CreateToken(id, note, hex string) (*Token, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		"INSERT INTO tokens (id, note, token, created_at) VALUES (?, ?, ?, ?)",
		id, note, hex, now,
	)
	if err != nil {
		return nil, err
	}
	return &Token{ID: id, Note: note, Token: hex, CreatedAt: now}, nil
}

// ListTokens returns all tokens with their hit counts.
func (s *Store) ListTokens() ([]Token, error) {
	rows, err := s.db.Query(`
		SELECT t.id, t.note, t.token, t.created_at, COUNT(i.id) as hit_count
		FROM tokens t
		LEFT JOIN interactions i ON i.token_id = t.id
		GROUP BY t.id
		ORDER BY t.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Note, &t.Token, &t.CreatedAt, &t.HitCount); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// DeleteToken deletes a token and cascades to interactions.
func (s *Store) DeleteToken(id string) error {
	res, err := s.db.Exec("DELETE FROM tokens WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// FindTokenByHex looks up a token by its hex string.
func (s *Store) FindTokenByHex(hex string) (*Token, error) {
	var t Token
	err := s.db.QueryRow(
		"SELECT id, note, token, created_at FROM tokens WHERE token = ?", hex,
	).Scan(&t.ID, &t.Note, &t.Token, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// RecordInteraction inserts a new interaction.
func (s *Store) RecordInteraction(i *Interaction) error {
	_, err := s.db.Exec(`
		INSERT INTO interactions (id, token_id, token, type, source_ip, timestamp,
			query_name, query_type, method, path, headers, body, raw_request)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.TokenID, i.Token, i.Type, i.SourceIP, i.Timestamp,
		i.QueryName, i.QueryType, i.Method, i.Path, i.Headers, i.Body, i.RawRequest,
	)
	return err
}

// ListInteractions returns interactions, optionally filtered by token ID.
func (s *Store) ListInteractions(tokenID string, offset, limit int) ([]Interaction, int, error) {
	var total int
	var args []any

	countQ := "SELECT COUNT(*) FROM interactions"
	listQ := `SELECT id, token_id, token, type, source_ip, timestamp,
		query_name, query_type, method, path, headers, body, raw_request
		FROM interactions`

	if tokenID != "" {
		countQ += " WHERE token_id = ?"
		listQ += " WHERE token_id = ?"
		args = append(args, tokenID)
	}

	if err := s.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQ += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	listArgs := append(args, limit, offset)

	rows, err := s.db.Query(listQ, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []Interaction
	for rows.Next() {
		var i Interaction
		var qn, qt, m, p, h, b, rr sql.NullString
		if err := rows.Scan(&i.ID, &i.TokenID, &i.Token, &i.Type, &i.SourceIP, &i.Timestamp,
			&qn, &qt, &m, &p, &h, &b, &rr); err != nil {
			return nil, 0, err
		}
		i.QueryName = qn.String
		i.QueryType = qt.String
		i.Method = m.String
		i.Path = p.String
		i.Headers = h.String
		i.Body = b.String
		i.RawRequest = rr.String
		items = append(items, i)
	}
	return items, total, rows.Err()
}

// ClearInteractions deletes interactions, optionally filtered by token ID.
func (s *Store) ClearInteractions(tokenID string) error {
	if tokenID != "" {
		_, err := s.db.Exec("DELETE FROM interactions WHERE token_id = ?", tokenID)
		return err
	}
	_, err := s.db.Exec("DELETE FROM interactions")
	return err
}

// GetConfig returns the callback configuration.
func (s *Store) GetConfig() (*CallbackConfig, error) {
	cfg := &CallbackConfig{ResponseIP: "127.0.0.1"}
	s.db.QueryRow("SELECT value FROM config WHERE key = 'domain'").Scan(&cfg.Domain)           //nolint:errcheck
	s.db.QueryRow("SELECT value FROM config WHERE key = 'response_ip'").Scan(&cfg.ResponseIP)  //nolint:errcheck
	return cfg, nil
}

// GetConfigValue returns a single config value by key.
func (s *Store) GetConfigValue(key string) (string, error) {
	var val string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&val)
	if err != nil {
		return "", err
	}
	return val, nil
}

// SetConfigValue sets a single config value by key.
func (s *Store) SetConfigValue(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

// SetConfig saves the callback configuration.
func (s *Store) SetConfig(cfg *CallbackConfig) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, kv := range [][2]string{
		{"domain", cfg.Domain},
		{"response_ip", cfg.ResponseIP},
	} {
		_, err := tx.Exec(
			"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			kv[0], kv[1],
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
