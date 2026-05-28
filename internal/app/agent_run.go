package app

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent runtime sidecar commands",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Run an agent inside a container (not yet implemented)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "quokka agent run: not yet implemented (PR-2)")
			return nil
		},
	})
	return cmd
}
