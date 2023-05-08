package snyk

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func NewSnykRootCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:                   "snyk",
		Short:                 "",
		Long:                  ``,
		Aliases:               []string{"s"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)

	cmd.AddCommand(NewPackageCommand())
	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
