// Package app holds the cobra wiring for the new quokka SaaS binary.
// The legacy CLI lives at cmd/* and is untouched.
package app

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the new SaaS entry point.
var rootCmd = &cobra.Command{
	Use:   "quokka",
	Short: "Quokka SaaS — LLM code review server, worker, and admin tooling",
	Long: `Quokka is a self-hosted code review SaaS.
This binary runs the web server, the background worker, schema migrations,
admin tasks, and the in-container agent sidecar.`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if globals.DSN == "" {
			globals.DSN = os.Getenv("QUOKKA_DSN")
		}
		if globals.DataRoot == "" {
			globals.DataRoot = os.Getenv("QUOKKA_DATA_ROOT")
		}
		return nil
	},
}

// globalFlags carries values shared across subcommands.
type globalFlags struct {
	DSN      string
	DataRoot string
}

var globals globalFlags

func init() {
	rootCmd.PersistentFlags().StringVar(&globals.DSN, "dsn", "",
		"DB DSN, e.g. sqlite:///data/quokka.db or postgres://user:pass@host/db (env QUOKKA_DSN)")
	rootCmd.PersistentFlags().StringVar(&globals.DataRoot, "data-root", "",
		"Filesystem root for per-repo embedding state and transcripts (env QUOKKA_DATA_ROOT)")

	rootCmd.AddCommand(newMigrateCmd())
	rootCmd.AddCommand(newServerCmd())
	rootCmd.AddCommand(newWorkerCmd())
	rootCmd.AddCommand(newAgentCmd())
	rootCmd.AddCommand(newAdminCmd())
}

// Execute runs the cobra command tree. Returns any error from the subcommand.
func Execute() error {
	return rootCmd.Execute()
}
