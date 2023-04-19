package commands

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"os"

	"github.com/snyk/parlay/pkg/ecosystems/packages"
	"github.com/snyk/parlay/pkg/parlay"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/spf13/cobra"
)

func NewEnrichCommand(logger *log.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "enrich <sbom>",
		Short: "Enrich an SBOM with ecosyste.ms data",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			var b []byte
			if args[0] == "-" {
				b, err = ioutil.ReadAll(bufio.NewReader(os.Stdin))
			} else {
				b, err = os.ReadFile(args[0])
			}
			if err != nil {
				panic(err)
			}

			bom := new(cdx.BOM)
			decoder := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON)
			if err = decoder.Decode(bom); err != nil {
				panic(err)
			}

			wg := sizedwaitgroup.New(40)

			var newcs []cdx.Component

			for _, component := range *bom.Components {
				wg.Add()
				go func(i string) {
					defer wg.Done()
					purl, _ := packageurl.FromString(i)
					update := query(purl)
					logger.Printf("Looking up: %s", i)
					// TODO catch out of range error in runtime
					component.Description = *(*update.JSON200).Description

					newcs = append(newcs, component)
				}(component.PackageURL)
			}

			wg.Wait()

			bom.Components = &newcs

			err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).Encode(bom)
		},
	}
	return &cmd
}

func query(i packageurl.PackageURL) packages.GetRegistryPackageResponse {
	resp, err := parlay.GetPackageData(i)
	if err != nil {
		panic(err)
	}
	return *resp
}
