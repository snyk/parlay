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
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run ecosystems command")
			}
		},
	}

	cmd.AddCommand(NewPackageCommand(logger))
	cmd.AddCommand(NewRepoCommand(logger))
	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
