package ecosystems

import (
	"os"

	"github.com/snyk/parlay/internal/flags"
	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/ecosystems"
	"github.com/snyk/parlay/lib/sbom"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewEnrichCommand(logger zerolog.Logger) *cobra.Command {
	var format *flags.FormatFlagVal

	cmd := cobra.Command{
		Use:   "enrich <sbom>",
		Short: "Enrich an SBOM with ecosyste.ms data",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			b, err := utils.GetUserInput(args[0], os.Stdin)
			if err != nil {
				logger.Fatal().Err(err).Msg("Problem reading input")
			}

			bom, err := sbom.UnmarshalSBOM(b, flags.FlagToSBOMFormat(format))
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to decode SBOM input")
			}

			if err := ecosystems.EnrichSBOM(bom); err != nil {
				logger.Fatal().Err(err).Msg("Failed to enrich SBOM")
			}

			if err := bom.Encode(os.Stdout); err != nil {
				logger.Fatal().Err(err).Msg("Failed to encode new SBOM")
			}
		},
	}

	format, err := flags.AddFormatFlag(&cmd)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to set up enrich command")
	}

	return &cmd
}
