package commands

import (
	"os"

	"github.com/snyk/parlay/internal/commands/ecosystems"
	"github.com/snyk/parlay/internal/commands/snyk"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewDefaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:                   "parlay",
		Short:                 "Enrich an SBOM with context from third party services",
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
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
	viper.BindPFlag("debug", cmd.PersistentFlags().Lookup("debug"))

	output := zerolog.ConsoleWriter{Out: os.Stderr}
	logger := zerolog.New(output).With().Timestamp().Logger()

	cmd.AddCommand(ecosystems.NewEcosystemsRootCommand(logger))
	cmd.AddCommand(snyk.NewSnykRootCommand(logger))

	return &cmd
}
