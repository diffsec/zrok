// Package migrations embeds the SQL migration files and exposes a runner
// that applies them via golang-migrate.
package migrations

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed sqlite/*.sql
var sqliteFS embed.FS

//go:embed postgres/*.sql
var postgresFS embed.FS

// Dialect identifies which migration set to use.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// FS returns the embedded sub-FS for the given dialect.
func FS(d Dialect) (fs.FS, error) {
	switch d {
	case DialectSQLite:
		return fs.Sub(sqliteFS, "sqlite")
	case DialectPostgres:
		return fs.Sub(postgresFS, "postgres")
	default:
		return nil, fmt.Errorf("unknown dialect %q", d)
	}
}

// newMigrator builds a *migrate.Migrate over the embedded source FS and the
// given *sql.DB. The dialect determines which database-driver to use.
func newMigrator(d Dialect, db *sql.DB) (*migrate.Migrate, error) {
	sub, err := FS(d)
	if err != nil {
		return nil, err
	}
	src, err := iofs.New(sub, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs: %w", err)
	}

	switch d {
	case DialectSQLite:
		drv, err := migratesqlite.WithInstance(db, &migratesqlite.Config{})
		if err != nil {
			return nil, fmt.Errorf("sqlite driver: %w", err)
		}
		return migrate.NewWithInstance("iofs", src, "sqlite", drv)
	case DialectPostgres:
		drv, err := migratepg.WithInstance(db, &migratepg.Config{})
		if err != nil {
			return nil, fmt.Errorf("pgx driver: %w", err)
		}
		return migrate.NewWithInstance("iofs", src, "pgx5", drv)
	}
	return nil, fmt.Errorf("unknown dialect %q", d)
}

// Up applies all up migrations. ErrNoChange becomes nil.
func Up(d Dialect, db *sql.DB) error {
	m, err := newMigrator(d, db)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// Down rolls back all migrations.
func Down(d Dialect, db *sql.DB) error {
	m, err := newMigrator(d, db)
	if err != nil {
		return err
	}
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// Steps runs n migrations (positive=up, negative=down).
func Steps(d Dialect, db *sql.DB, n int) error {
	m, err := newMigrator(d, db)
	if err != nil {
		return err
	}
	if err := m.Steps(n); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
