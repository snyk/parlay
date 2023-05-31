package deps

import (
	"fmt"
  "encoding/json"

	"github.com/snyk/parlay/lib/deps"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewRepoCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "repo <repo>",
		Short: "Return repo info from deps.dev",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			repo, err := deps.GetRepoData(args[0])
			if err != nil {
				logger.Fatal().Err(err).Msg("Error retrieving data from deps.dev")
			}
      repository, err := json.Marshal(repo)
			if err != nil {
				logger.Fatal().Err(err).Msg("Error with JSON response from deps.dev")
			}
			fmt.Print(string(repository))
		},
	}
	return &cmd
}
