package ecosystems

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/ecosystems"
	"github.com/snyk/parlay/lib/sbom"
)

func NewEnrichCommand(logger *zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "enrich <sbom>",
		Short: "Enrich an SBOM with ecosyste.ms data",
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

			ecosystems.EnrichSBOM(doc, logger)

			if err := doc.Encode(os.Stdout); err != nil {
				logger.Fatal().Err(err).Msg("Failed to encode new SBOM")
			}
		},
	}
	return &cmd
}
