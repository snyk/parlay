package scorecard

import (
	"net/http"
	"strings"

	"github.com/snyk/parlay/lib/ecosystems"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
)

func enrichExternalReference(component cdx.Component, url string, comment string, refType cdx.ExternalReferenceType) cdx.Component {
	ext := cdx.ExternalReference{
		URL:     url,
		Comment: comment,
		Type:    refType,
	}
	if component.ExternalReferences == nil {
		component.ExternalReferences = &[]cdx.ExternalReference{ext}
	} else {
		*component.ExternalReferences = append(*component.ExternalReferences, ext)
	}
	return component
}

func EnrichSBOM(bom *cdx.BOM) *cdx.BOM {
	if bom.Components == nil {
		return bom
	}

	wg := sizedwaitgroup.New(20)
	newComponents := make([]cdx.Component, len(*bom.Components))
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			purl, _ := packageurl.FromString(component.PackageURL)
			resp, err := ecosystems.GetPackageData(purl)
			if err == nil && resp.JSON200 != nil && resp.JSON200.RepositoryUrl != nil {
				scorecardUrl := strings.ReplaceAll(*resp.JSON200.RepositoryUrl, "https://", "https://api.securityscorecards.dev/projects/")
				response, err := http.Get(scorecardUrl)
				if err == nil {
					defer response.Body.Close()
					if response.StatusCode == http.StatusOK {
						component = enrichExternalReference(component, scorecardUrl, "OpenSSF Scorecard", cdx.ERTypeOther)
					}
				}
			}
			newComponents[i] = component
			wg.Done()
		}(component, i)
	}
	wg.Wait()
	bom.Components = &newComponents

	return bom
}
