package lib

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
)

func EnrichSBOM(bom *cdx.BOM) *cdx.BOM {
	wg := sizedwaitgroup.New(20)

	if bom.Components == nil {
		return bom
	}

	newComponents := make([]cdx.Component, len(*bom.Components))

	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			purl, _ := packageurl.FromString(component.PackageURL)
			resp, err := GetPackageData(purl)
			if err == nil {
				packageData := resp.JSON200
				if packageData != nil {
					if packageData.Description != nil {
						component.Description = *packageData.Description
					}
					if packageData.Licenses != nil {
						licences := cdx.LicenseChoice{Expression: *packageData.Licenses}
						component.Licenses = &cdx.Licenses{licences}
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
