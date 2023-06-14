package scorecard

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewRootCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "scorecard",
		Short:                 "Commands for using parlay with OpenSSF Scorecard",
		Aliases:               []string{"s"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run scorecard command")
			}
		},
	}

	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
