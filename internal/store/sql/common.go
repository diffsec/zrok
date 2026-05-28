// Package sql provides shared helpers for the SQLite and Postgres adapters.
package sql

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	// Driver imports register their respective sql drivers.
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Dialect is one of "sqlite" or "postgres".
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// DetectDialect parses a DSN like "sqlite:///path/to.db" or
// "postgres://user:pass@host/db" and returns the dialect plus the connection
// string suitable for sql.Open.
func DetectDialect(dsn string) (Dialect, string, error) {
	switch {
	case strings.HasPrefix(dsn, "sqlite://"):
		return DialectSQLite, strings.TrimPrefix(dsn, "sqlite://"), nil
	case strings.HasPrefix(dsn, "sqlite:"):
		return DialectSQLite, strings.TrimPrefix(dsn, "sqlite:"), nil
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return DialectPostgres, dsn, nil
	default:
		return "", "", fmt.Errorf("unrecognized DSN scheme: %s", dsn)
	}
}

// Open opens a *sql.DB for the given DSN. SQLite gets WAL + foreign keys
// enabled. Postgres uses pgx-stdlib defaults.
func Open(dsn string) (Dialect, *sql.DB, error) {
	d, conn, err := DetectDialect(dsn)
	if err != nil {
		return "", nil, err
	}
	switch d {
	case DialectSQLite:
		db, err := openSQLite(conn)
		return d, db, err
	case DialectPostgres:
		db, err := openPostgres(conn)
		return d, db, err
	}
	return "", nil, fmt.Errorf("unknown dialect")
}

func openSQLite(path string) (*sql.DB, error) {
	// modernc.org/sqlite uses a query-string form for pragmas.
	if !strings.Contains(path, "?") {
		path += "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(1) // sqlite WAL still needs serialized writes
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}
	return db, nil
}

func openPostgres(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	return db, nil
}
