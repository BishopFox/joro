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

CREATE TABLE IF NOT EXISTS team_shared_configs (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL DEFAULT '',
	project_id  TEXT NOT NULL DEFAULT '',
	author      TEXT NOT NULL,
	config      TEXT NOT NULL,
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_team_shared_configs_time ON team_shared_configs(created_at DESC);

CREATE TABLE IF NOT EXISTS team_collab_requests (
	id          TEXT PRIMARY KEY,
	requestor   TEXT NOT NULL,
	project_id  TEXT NOT NULL DEFAULT '',
	note        TEXT NOT NULL DEFAULT '',
	config      TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'open',
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_team_collab_time ON team_collab_requests(created_at DESC);
`

// MigrateDB creates team tables in an existing database.
func MigrateDB(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// Columns added after the initial release; CREATE TABLE IF NOT EXISTS won't
	// add them to a pre-existing table, so add them idempotently.
	for _, col := range []string{
		"ALTER TABLE team_chat ADD COLUMN ref_id TEXT",
		"ALTER TABLE team_chat ADD COLUMN ref_type TEXT",
	} {
		if _, err := db.Exec(col); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
				return err
			}
		}
	}
	return nil
}
