package ecosystems

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewEcosystemsRootCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "ecosystems",
		Short:                 "Commands for using parlay with ecosystem.ms",
		Aliases:               []string{"e"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	cmd.AddCommand(NewPackageCommand(logger))
	cmd.AddCommand(NewRepoCommand(logger))
	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
