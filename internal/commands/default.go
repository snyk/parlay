package commands

import (
	"os"
	"time"

	"github.com/snyk/parlay/internal/commands/ecosystems"
	"github.com/snyk/parlay/internal/commands/snyk"

	"github.com/rs/zerolog"
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

	output := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}

	logger := zerolog.New(output).With().Timestamp().Logger()

	cmd.AddCommand(ecosystems.NewEcosystemsRootCommand(logger))
	cmd.AddCommand(snyk.NewSnykRootCommand(logger))

	return &cmd
}
