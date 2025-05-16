package osv

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewRootCommand(logger *zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "osv",
		Short:                 "Commands for using parlay with Open Source Vulnerability database content",
		Aliases:               []string{"s"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run osv command")
			}
		},
	}

	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
