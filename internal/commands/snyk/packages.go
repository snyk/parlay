package snyk

import (
	"fmt"
	"log"

	"github.com/snyk/parlay/lib"

	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
)

func NewPackageCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "package <purl> ",
		Short: "Return package vulnerabilities from Snyk",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			purl, err := packageurl.FromString(args[0])
			if err != nil {
				log.Fatal(err)
			}
			resp, err := lib.GetPackageVulnerabilities(purl)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Print(string(resp.Body))
		},
	}
	return &cmd
}
