package ecosystems

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func NewEcosystemsRootCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:                   "ecosystems",
		Short:                 "",
		Long:                  ``,
		Aliases:               []string{"e"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)

	cmd.AddCommand(NewPackageCommand())
	cmd.AddCommand(NewRepoCommand())
	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
