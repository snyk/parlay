package deps

import (
	"encoding/json"
	"fmt"

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
			proj, err := deps.GetRepoData(args[0])
			if err != nil {
				logger.Fatal().Err(err).Msg("An error occured")
			}
			b, err := json.Marshal(proj)
			fmt.Print(string(b))
		},
	}
	return &cmd
}
