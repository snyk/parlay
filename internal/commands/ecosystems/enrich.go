package ecosystems

import (
	"os"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/ecosystems"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewEnrichCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "enrich <sbom>",
		Short: "Enrich an SBOM with ecosyste.ms data",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			b, err := utils.GetUserInput(args[0], os.Stdin)
			if err != nil {
				logger.Fatal().Err(err).Msg("Problem reading input")
			}

			maybeBOM, serialize := utils.IdentifySBOM(b)

			switch bom := maybeBOM.(type) {
			case *cdx.BOM:
				bom = ecosystems.EnrichSBOM(bom)
				if err := serialize(bom, os.Stdout); err != nil {
					logger.Fatal().Err(err).Msg("Failed to write to Stdout")
				}
			default:
				logger.Fatal().Err(err).Msg("Input needs to be a valid CycloneDX SBOM")
			}
		},
	}
	return &cmd
}
