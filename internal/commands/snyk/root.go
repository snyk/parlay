package snyk

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewSnykRootCommand(logger *zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "snyk",
		Short:                 "Commands for using parlay with Snyk",
		Aliases:               []string{"s"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run snyk command")
			}
		},
	}

	cmd.AddCommand(NewPackageCommand(logger))
	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
