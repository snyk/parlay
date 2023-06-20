package scorecard

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/sbom"
	"github.com/snyk/parlay/lib/scorecard"
)

func NewEnrichCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "enrich <sbom>",
		Short: "Enrich an SBOM with OpenSSF Scorecard data",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			b, err := utils.GetUserInput(args[0], os.Stdin)
			if err != nil {
				logger.Fatal().Err(err).Msg("Problem reading input")
			}

			doc, err := sbom.DecodeSBOMDocument(b)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read SBOM input")
			}

			scorecard.EnrichSBOM(doc)

			if err := doc.Encode(os.Stdout); err != nil {
				logger.Fatal().Err(err).Msg("Failed to encode new SBOM")
			}
		},
	}
	return &cmd
}
