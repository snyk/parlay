package snyk

import (
	"bytes"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/snyk"
)

func NewEnrichCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "enrich <sbom>",
		Short: "Enrich an SBOM with Snyk data",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			b, err := utils.GetUserInput(args[0], os.Stdin)
			if err != nil {
				logger.Fatal().Err(err).Msg("Problem reading input")
			}

			bom := new(cdx.BOM)
			decoder := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON)
			if err = decoder.Decode(bom); err != nil {
				logger.Fatal().Err(err).Msg("Problem decoding SBOM")
			}

			bom = snyk.EnrichSBOM(bom)
			err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).Encode(bom)
			if err != nil {
				logger.Fatal().Err(err).Msg("Problem encoding SBOM")
			}
		},
	}
	return &cmd
}
