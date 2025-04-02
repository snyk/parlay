package snyk

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/sbom"
	"github.com/snyk/parlay/lib/snyk"
)

func NewEnrichCommand(logger *zerolog.Logger) *cobra.Command {
	var omitWatermark bool

	cmd := cobra.Command{
		Use:     "enrich <sbom>",
		Short:   "Enrich an SBOM with Snyk data",
		Args:    cobra.ExactArgs(1),
		Version: utils.GetVersion(),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config()
			svc := snyk.NewService(cfg, logger)

			b, err := utils.GetUserInput(args[0], os.Stdin)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read input")
			}

			doc, err := sbom.DecodeSBOMDocument(b)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read SBOM input")
			}

			svc.EnrichSBOM(doc)

			if !omitWatermark {
				sbom.AddParlayWatermark(doc, cmd.Version)
			}

			if err := doc.Encode(os.Stdout); err != nil {
				logger.Fatal().Err(err).Msg("Failed to encode new SBOM")
			}
		},
	}

	cmd.Flags().BoolVar(&omitWatermark, "omit-watermark", false, "omit parlay watermark")

	return &cmd
}
