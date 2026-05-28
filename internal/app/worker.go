package app

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newWorkerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Run the background job worker (not yet implemented)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "quokka worker: not yet implemented (PR-2)")
			return nil
		},
	}
}
