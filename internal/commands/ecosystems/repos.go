package ecosystems

import (
	"fmt"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/snyk/parlay/lib/ecosystems"
)

func NewRepoCommand(logger *zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "repo <host> <repo>",
		Short: "Return repo info from ecosyste.ms",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := ecosystems.GetRepoData(args[0])
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to get repository data from ecosyste.ms")
			}
			fmt.Print(string(resp.Body))
		},
	}
	return &cmd
}
