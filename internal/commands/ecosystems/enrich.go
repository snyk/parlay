package ecosystems

import (
	"bufio"
	"bytes"
	"io"
	"os"

	"github.com/snyk/parlay/lib"

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
			var err error
			var b []byte
			if args[0] == "-" {
				b, err = io.ReadAll(bufio.NewReader(os.Stdin))
			} else {
				b, err = os.ReadFile(args[0])
			}
			if err != nil {
				logger.Fatal().Err(err).Msg("Couldn't opened the file")
			}

			bom := new(cdx.BOM)
			decoder := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON)
			if err = decoder.Decode(bom); err != nil {
				logger.Fatal().Err(err).Msg("Input needs to be a valid CycloneDX SBOM")
			}

			bom = lib.EnrichSBOMWithEcosystems(bom)
			err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).Encode(bom)
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to envode new SBOM")
			}
		},
	}
	return &cmd
}
