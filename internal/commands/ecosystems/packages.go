package ecosystems

import (
	"fmt"

	"github.com/snyk/parlay/lib/ecosystems"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewPackageCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "package <purl> ",
		Short: "Return package info from ecosyste.ms",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			purl, err := packageurl.FromString(args[0])
			if err != nil {
				logger.Fatal().Err(err)
			}
			resp, err := ecosystems.GetPackageData(purl)
			if err != nil {
				logger.Fatal().Err(err)
			}
			fmt.Print(string(resp.Body))
		},
	}
	return &cmd
}
