package commands

import (
	"github.com/snyk/parlay/internal/commands/ecosystems"
	"github.com/snyk/parlay/internal/commands/snyk"

	"github.com/spf13/cobra"
)

func NewDefaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:                   "parlay",
		Short:                 "",
		Long:                  ``,
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
  cmd.CompletionOptions.HiddenDefaultCmd = true

	cmd.AddCommand(ecosystems.NewEcosystemsRootCommand())
	cmd.AddCommand(snyk.NewSnykRootCommand())

	return &cmd
}
