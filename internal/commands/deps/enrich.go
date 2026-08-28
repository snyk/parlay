package deps

import (
	"os"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/deps"
	"github.com/snyk/parlay/lib/sbom"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewEnrichCommand(logger *zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "enrich <sbom>",
		Short: "Enrich an SBOM with deps.dev data",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			b, err := utils.GetUserInput(args[0], os.Stdin)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read input")
			}

			doc, err := sbom.DecodeSBOMDocument(b)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read SBOM input")
			}

			deps.EnrichSBOM(doc, logger)

			if err := doc.Encode(os.Stdout); err != nil {
				logger.Fatal().Err(err).Msg("Failed to encode new SBOM")
			}
		},
	}
	return &cmd
}
