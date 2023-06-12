package version

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func GetVersion(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "version",
		Short:                 "Commands for using parlay with Snyk",
		Aliases:               []string{"s"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			tag, err := getCurrentTag()
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println("Current version of the application :", tag)
		},
	}

	return &cmd
}

// git tag --points-at HEAD
func getCurrentTag() (string, error) {
	cmd := exec.Command("git", "describe", "--tags", "--abbrev=0")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	tag := strings.TrimSpace(string(output))
	return tag, nil
}
