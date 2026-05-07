package callback

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS config (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
	id         TEXT PRIMARY KEY,
	note       TEXT NOT NULL DEFAULT '',
	token      TEXT NOT NULL UNIQUE,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS interactions (
	id          TEXT PRIMARY KEY,
	token_id    TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
	token       TEXT NOT NULL,
	type        TEXT NOT NULL,
	source_ip   TEXT NOT NULL,
	timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	query_name  TEXT,
	query_type  TEXT,
	method      TEXT,
	path        TEXT,
	headers     TEXT,
	body        TEXT,
	raw_request TEXT
);

CREATE INDEX IF NOT EXISTS idx_interactions_token_id ON interactions(token_id);
CREATE INDEX IF NOT EXISTS idx_interactions_timestamp ON interactions(timestamp DESC);

CREATE TABLE IF NOT EXISTS xss_probes (
	id            TEXT PRIMARY KEY,
	name          TEXT NOT NULL DEFAULT '',
	probe_id      TEXT NOT NULL UNIQUE,
	collect_pages TEXT NOT NULL DEFAULT '',
	chainload_uri TEXT NOT NULL DEFAULT '',
	created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS xss_fires (
	id            TEXT PRIMARY KEY,
	probe_id      TEXT NOT NULL REFERENCES xss_probes(id) ON DELETE CASCADE,
	probe_token   TEXT NOT NULL,
	url           TEXT NOT NULL,
	origin        TEXT NOT NULL DEFAULT '',
	referrer      TEXT NOT NULL DEFAULT '',
	user_agent    TEXT NOT NULL DEFAULT '',
	cookies       TEXT NOT NULL DEFAULT '',
	page_title    TEXT NOT NULL DEFAULT '',
	dom           TEXT NOT NULL DEFAULT '',
	screenshot    TEXT NOT NULL DEFAULT '',
	source_ip     TEXT NOT NULL DEFAULT '',
	in_iframe      INTEGER NOT NULL DEFAULT 0,
	browser_time   TEXT NOT NULL DEFAULT '',
	page_text      TEXT NOT NULL DEFAULT '',
	injection_key  TEXT NOT NULL DEFAULT '',
	fired_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_xss_fires_probe ON xss_fires(probe_id);
CREATE INDEX IF NOT EXISTS idx_xss_fires_time  ON xss_fires(fired_at DESC);

CREATE TABLE IF NOT EXISTS xss_collected_pages (
	id           TEXT PRIMARY KEY,
	fire_id      TEXT NOT NULL REFERENCES xss_fires(id) ON DELETE CASCADE,
	url          TEXT NOT NULL,
	html         TEXT NOT NULL DEFAULT '',
	collected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_xss_collected_pages_fire ON xss_collected_pages(fire_id);
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

	// Migrate: rename "name" column to "note" for existing databases.
	var hasNameCol bool
	rows, err := db.Query("PRAGMA table_info(tokens)")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, typ string
			var notNull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err == nil {
				if name == "name" {
					hasNameCol = true
				}
			}
		}
	}
	if hasNameCol {
		db.Exec("ALTER TABLE tokens RENAME COLUMN name TO note") //nolint:errcheck
	}

	// Migrate: add new columns to xss_fires for existing databases.
	migrateAddColumn(db, "xss_fires", "page_text", "TEXT NOT NULL DEFAULT ''")
	migrateAddColumn(db, "xss_fires", "injection_key", "TEXT NOT NULL DEFAULT ''")

	// Migrate: add new columns to xss_probes for existing databases.
	migrateAddColumn(db, "xss_probes", "collect_pages", "TEXT NOT NULL DEFAULT ''")
	migrateAddColumn(db, "xss_probes", "chainload_uri", "TEXT NOT NULL DEFAULT ''")

	return db, nil
}

// migrateAddColumn adds a column to a table if it doesn't already exist.
func migrateAddColumn(db *sql.DB, table, column, colDef string) {
	var exists bool
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err == nil {
			if name == column {
				exists = true
			}
		}
	}
	if !exists {
		db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + colDef) //nolint:errcheck
	}
}
