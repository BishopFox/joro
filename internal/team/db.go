package team

import (
	"database/sql"
	"strings"
)

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

CREATE TABLE IF NOT EXISTS team_flagged_requests (
	id          TEXT PRIMARY KEY,
	host        TEXT NOT NULL DEFAULT '',
	method      TEXT NOT NULL DEFAULT '',
	url         TEXT NOT NULL DEFAULT '',
	status      INTEGER NOT NULL DEFAULT 0,
	req_raw     BLOB,
	resp_raw    BLOB,
	truncated   INTEGER NOT NULL DEFAULT 0,
	note        TEXT NOT NULL DEFAULT '',
	author      TEXT NOT NULL,
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_team_flagged_time ON team_flagged_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_team_flagged_host ON team_flagged_requests(host);
`

// MigrateDB creates team tables in an existing database.
func MigrateDB(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// team_chat.ref_id was added after the initial release; CREATE TABLE IF NOT
	// EXISTS won't add it to a pre-existing table, so add it idempotently.
	if _, err := db.Exec("ALTER TABLE team_chat ADD COLUMN ref_id TEXT"); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}
