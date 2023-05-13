package ecosystems

import (
	"fmt"

	"github.com/snyk/parlay/lib/ecosystems"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewRepoCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "repo <host> <repo>",
		Short: "Return repo info from ecosyste.ms",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := ecosystems.GetRepoData(args[0])
			if err != nil {
				logger.Fatal().Err(err).Msg("An error occured")
			}
			fmt.Print(string(resp.Body))
		},
	}
	return &cmd
}
