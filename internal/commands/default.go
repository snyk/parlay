package commands

import (
	"log"
	"os"

	"github.com/snyk/parlay/internal/commands/ecosystems"

	"github.com/spf13/cobra"
)

func NewDefaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:          "parlay",
		Short:        "",
		Long:         ``,
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)

	cmd.AddCommand(NewEnrichCommand(logger))
	cmd.AddCommand(ecosystems.NewEcosystemsRootCommand())

	return &cmd
}
