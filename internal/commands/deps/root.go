package deps

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewDepsRootCommand(logger *zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "deps",
		Short:                 "Commands for using parlay with deps.dev",
		Aliases:               []string{"d"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run deps command")
			}
		},
	}

	cmd.AddCommand(NewRepoCommand(logger))

	return &cmd
}
