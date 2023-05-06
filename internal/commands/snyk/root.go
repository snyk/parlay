package snyk

import (
	"github.com/spf13/cobra"
)

func NewSnykRootCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:          "snyk",
		Short:        "",
		Long:         ``,
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	cmd.AddCommand(NewPackageCommand())

	return &cmd
}
