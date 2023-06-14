package commands

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/snyk/parlay/internal/commands/deps"
	"github.com/snyk/parlay/internal/commands/ecosystems"
	"github.com/snyk/parlay/internal/commands/scorecard"
	"github.com/snyk/parlay/internal/commands/snyk"
)

func NewDefaultCommand() *cobra.Command {
	output := zerolog.ConsoleWriter{Out: os.Stderr}
	logger := zerolog.New(output).With().Timestamp().Logger()

	cmd := cobra.Command{
		Use:                   "parlay",
		Short:                 "Enrich an SBOM with context from third party services",
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run parlay command")
			}
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if viper.GetBool("debug") {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			} else {
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			}
		},
	}
	cmd.CompletionOptions.HiddenDefaultCmd = true

	cmd.PersistentFlags().Bool("debug", false, "")
	viper.BindPFlag("debug", cmd.PersistentFlags().Lookup("debug")) //nolint:errcheck

	cmd.AddCommand(ecosystems.NewEcosystemsRootCommand(logger))
	cmd.AddCommand(snyk.NewSnykRootCommand(logger))
	cmd.AddCommand(deps.NewDepsRootCommand(logger))
	cmd.AddCommand(scorecard.NewRootCommand(logger))

	return &cmd
}
