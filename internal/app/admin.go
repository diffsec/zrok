package app

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/store"
	"github.com/spf13/cobra"

	// register concrete adapters
	_ "github.com/diffsec/quokka/internal/store/sql/postgres"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
)

func newAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrative operations",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "rotate-keys",
		Short: "Re-encrypt every encrypted column with the current master key",
		Long: `Rotate the master encryption key.

Reads each encrypted row, decrypts with the matching key_version (current or
legacy slot QUOKKA_MASTER_KEY_OLD), and re-encrypts with QUOKKA_MASTER_KEY.
Run during a maintenance window.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dsn := globals.DSN
			if dsn == "" {
				return fmt.Errorf("--dsn is required")
			}
			ctx := context.Background()
			stores, err := store.Open(ctx, store.Config{DSN: dsn, DataRoot: globals.DataRoot})
			if err != nil {
				return err
			}
			defer stores.Close()

			n, err := stores.Providers.RotateKeys(ctx)
			if err != nil {
				return fmt.Errorf("rotate providers: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "providers rotated: %d\n", n)
			return nil
		},
	})
	return cmd
}
