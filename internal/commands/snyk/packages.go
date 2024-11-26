package snyk

import (
	"fmt"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/snyk/parlay/lib/snyk"
)

func NewPackageCommand(logger *zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "package <purl>",
		Short: "Return package vulnerabilities from Snyk",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			conf := config()

			purl, err := packageurl.FromString(args[0])
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to parse PackageURL")
			}

			logger.
				Debug().
				Str("purl", args[0]).
				Msg("Looking up package vulnerabilities from Snyk")

			auth, err := snyk.AuthFromToken(conf.APIToken)
			if err != nil {
				logger.
					Fatal().
					Err(err).
					Msg("Failed to get API credentials")
			}

			orgID, err := snyk.SnykOrgID(conf, auth)
			if err != nil {
				logger.
					Fatal().
					Err(err).
					Msg("Failed to look up user info")
			}

			resp, err := snyk.GetPackageVulnerabilities(conf, &purl, auth, orgID)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to look up package vulnerabilities")
			}

			fmt.Print(string(resp.Body))
		},
	}
	return &cmd
}
