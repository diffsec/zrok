package app

import (
	"database/sql"
	"fmt"
	"strconv"

	migrations "github.com/diffsec/quokka/db/migrations"
	sqlcommon "github.com/diffsec/quokka/internal/store/sql"
	"github.com/spf13/cobra"
)

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Manage database schema migrations",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, db, err := openMigrate()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := migrations.Up(toMigrationDialect(d), db); err != nil {
				return fmt.Errorf("migrate up: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "migrations applied")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "down",
		Short: "Roll back all migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, db, err := openMigrate()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := migrations.Down(toMigrationDialect(d), db); err != nil {
				return fmt.Errorf("migrate down: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "migrations rolled back")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "steps [n]",
		Short: "Run n migrations (positive=up, negative=down)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid step count %q: %w", args[0], err)
			}
			d, db, err := openMigrate()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := migrations.Steps(toMigrationDialect(d), db, n); err != nil {
				return fmt.Errorf("migrate steps: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ran %d step(s)\n", n)
			return nil
		},
	})
	return cmd
}

func openMigrate() (sqlcommon.Dialect, *sql.DB, error) {
	if globals.DSN == "" {
		return "", nil, fmt.Errorf("--dsn is required (or set QUOKKA_DSN)")
	}
	return sqlcommon.Open(globals.DSN)
}

func toMigrationDialect(d sqlcommon.Dialect) migrations.Dialect {
	switch d {
	case sqlcommon.DialectSQLite:
		return migrations.DialectSQLite
	case sqlcommon.DialectPostgres:
		return migrations.DialectPostgres
	}
	return migrations.DialectSQLite
}
