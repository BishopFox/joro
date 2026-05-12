package notes

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS notes (
	id         TEXT PRIMARY KEY,
	host       TEXT NOT NULL,
	content    TEXT NOT NULL,
	author     TEXT NOT NULL DEFAULT 'operator',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notes_host ON notes(host);
CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_at DESC);
`

// OpenDB opens (or creates) the SQLite database at path and runs migrations.
func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(wal)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// Notes are ephemeral per-session; clear any leftovers from a previous run.
	// Persistent notes are saved in project config JSON files and restored on load.
	if _, err := db.Exec("DELETE FROM notes"); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
