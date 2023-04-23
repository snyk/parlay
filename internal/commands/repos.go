package commands

import (
	"fmt"
	"log"

	"github.com/snyk/parlay/lib"

	"github.com/spf13/cobra"
)

func NewRepoCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "repo <host> <repo>",
		Short: "Return repo info from ecosyste.ms",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := lib.GetRepoData(args[0])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Print(string(resp.Body))
		},
	}
	return &cmd
}
