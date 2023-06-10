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
			_ = cmd.Help()
		},
	}

	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
