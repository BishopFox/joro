package team

import "database/sql"

const schema = `
CREATE TABLE IF NOT EXISTS team_chat (
	id         TEXT PRIMARY KEY,
	author     TEXT NOT NULL,
	text       TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_team_chat_time ON team_chat(created_at DESC);

CREATE TABLE IF NOT EXISTS team_notes (
	id         TEXT PRIMARY KEY,
	host       TEXT NOT NULL DEFAULT '',
	content    TEXT NOT NULL,
	author     TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_team_notes_host ON team_notes(host);
CREATE INDEX IF NOT EXISTS idx_team_notes_time ON team_notes(created_at DESC);

CREATE TABLE IF NOT EXISTS team_connections (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	nickname     TEXT NOT NULL,
	ip           TEXT NOT NULL,
	connected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_team_connections_time ON team_connections(connected_at DESC);
`

// MigrateDB creates team tables in an existing database.
func MigrateDB(db *sql.DB) error {
	_, err := db.Exec(schema)
	return err
}
