package ecosystems

import (
	"github.com/spf13/cobra"
)

func NewEcosystemsRootCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:          "ecosystems",
		Short:        "",
		Long:         ``,
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	cmd.AddCommand(NewPackageCommand())
	cmd.AddCommand(NewRepoCommand())

	return &cmd
}
