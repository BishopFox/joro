package detect

import "regexp"

// Database-error signatures, one per DBMS. These are the single source of truth
// shared by the passive sql-error-* rules (rules_builtin.go) and the active
// SQL-injection rule (internal/activescan/sqli), which runs them against a probe
// response to confirm error-based SQLi. Keeping one copy stops the two from
// drifting.
const (
	SQLErrMySQL    = `(?i)(?:You have an error in your SQL syntax|Warning: mysqli?_[a-z_]+\(\)|MySQLSyntaxErrorException|com\.mysql\.(?:jdbc|cj)|check the manual that corresponds to your (?:MySQL|MariaDB))`
	SQLErrPostgres = `(?i)(?:PG::[A-Za-z]+Error|org\.postgresql\.util\.PSQLException|pg_query\(\)|unterminated quoted string at or near|invalid input syntax for)`
	SQLErrMSSQL    = `(?i)(?:Unclosed quotation mark after the character string|Incorrect syntax near|System\.Data\.SqlClient\.SqlException|Microsoft OLE DB Provider for SQL Server|\[SQL Server\])`
	SQLErrOracle   = `\b(ORA-\d{5})\b`
	SQLErrSQLite   = `(?i)(?:SQLite3?::[A-Za-z]+|sqlite3\.(?:Operational|Programming)Error|SQLITE_ERROR|unrecognized token:|no such table:)`
	SQLErrODBC     = `(?i)(?:\[Microsoft\]\[ODBC|Microsoft JET Database Engine|DB2 SQL error|SQLSTATE\[[0-9A-Z]{5}\])`
)

type sqlErrorSig struct {
	engine string
	re     *regexp.Regexp
}

var sqlErrorSigs = []sqlErrorSig{
	{"MySQL", regexp.MustCompile(SQLErrMySQL)},
	{"PostgreSQL", regexp.MustCompile(SQLErrPostgres)},
	{"SQL Server", regexp.MustCompile(SQLErrMSSQL)},
	{"Oracle", regexp.MustCompile(SQLErrOracle)},
	{"SQLite", regexp.MustCompile(SQLErrSQLite)},
	{"ODBC/JET/DB2", regexp.MustCompile(SQLErrODBC)},
}

// MatchSQLError reports whether body contains a database engine's error message,
// returning the engine name and the matched text as evidence.
func MatchSQLError(body []byte) (engine, evidence string, ok bool) {
	for _, s := range sqlErrorSigs {
		if loc := s.re.FindString(string(body)); loc != "" {
			return s.engine, loc, true
		}
	}
	return "", "", false
}
