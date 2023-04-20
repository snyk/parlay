package commands

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"os"

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

			wg := sizedwaitgroup.New(20)

      newComponents := make([]cdx.Component, len(*bom.Components))

			for i, component := range *bom.Components {
				wg.Add()
				go func(component cdx.Component, i int) {
					purl, _ := packageurl.FromString(component.PackageURL)
					update := query(purl)
					//logger.Printf("Looking up: %s", i)
					component.Description = update
          //logger.Printf("Desc for %s: %s", i, update)
					newComponents[i] = component
					wg.Done()
				}(component, i)
			}

			wg.Wait()

			bom.Components = &newComponents

			err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).Encode(bom)
		},
	}
	return &cmd
}

func query(i packageurl.PackageURL) string {
	resp, err := parlay.GetPackageData(i)
	if err != nil {
		panic(err)
	}
  return *resp.JSON200.Description
}
