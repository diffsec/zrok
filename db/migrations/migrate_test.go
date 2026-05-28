package migrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "modernc.org/sqlite"
)

func TestSQLite_UpDownUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "migrate-test.db") +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := Up(DialectSQLite, db); err != nil {
		t.Fatalf("first up: %v", err)
	}
	assertTablesExist(t, db, []string{"organizations", "providers", "findings", "memories_fts"})

	if err := Down(DialectSQLite, db); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertTablesGone(t, db, []string{"organizations", "providers", "findings"})

	if err := Up(DialectSQLite, db); err != nil {
		t.Fatalf("second up: %v", err)
	}
	assertTablesExist(t, db, []string{"organizations", "providers", "findings"})
}

func TestPostgres_UpDownUp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("quokka_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		t.Skipf("docker unavailable, skipping postgres test: %v", err)
	}
	defer func() {
		_ = container.Terminate(ctx)
	}()

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("conn string: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()

	if err := Up(DialectPostgres, db); err != nil {
		t.Fatalf("first up: %v", err)
	}
	assertTablesExist(t, db, []string{"organizations", "providers", "findings"})

	if err := Down(DialectPostgres, db); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertTablesGone(t, db, []string{"organizations", "providers", "findings"})

	if err := Up(DialectPostgres, db); err != nil {
		t.Fatalf("second up: %v", err)
	}
	assertTablesExist(t, db, []string{"organizations", "providers", "findings"})
}

func assertTablesExist(t *testing.T, db *sql.DB, names []string) {
	t.Helper()
	for _, n := range names {
		var got string
		if err := db.QueryRow(`SELECT table_name FROM information_schema.tables WHERE table_name=$1`, n).Scan(&got); err != nil {
			// Fall back to sqlite query.
			if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name=?`, n).Scan(&got); err != nil {
				t.Fatalf("table %q not present: %v", n, err)
			}
		}
	}
}

func assertTablesGone(t *testing.T, db *sql.DB, names []string) {
	t.Helper()
	for _, n := range names {
		var got string
		// sqlite check
		errSQLite := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, n).Scan(&got)
		errPG := db.QueryRow(`SELECT table_name FROM information_schema.tables WHERE table_name=$1`, n).Scan(&got)
		if errSQLite == nil || errPG == nil {
			t.Fatalf("table %q still present after down (sqliteErr=%v pgErr=%v)", n, errSQLite, errPG)
		}
	}
}
