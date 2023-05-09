package snyk

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
		Short: "Enrich an SBOM with Snyk data",
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
				logger.Fatal().Err(err).Msg("Problem reading file")
			}

			bom := new(cdx.BOM)
			decoder := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON)
			if err = decoder.Decode(bom); err != nil {
				logger.Fatal().Err(err).Msg("Problem decoding SBOM")
			}

			bom = lib.EnrichSBOMWithSnyk(bom)
			err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).Encode(bom)
			if err != nil {
				logger.Fatal().Err(err).Msg("Problem encoding SBOM")
			}
		},
	}
	return &cmd
}
