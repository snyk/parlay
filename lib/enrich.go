package lib

import (
	"github.com/snyk/parlay/ecosystems/packages"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
)

func enrichDescription(component cdx.Component, packageData *packages.Package) cdx.Component {
	if packageData.Description != nil {
		component.Description = *packageData.Description
	}
	return component
}

func enrichLicense(component cdx.Component, packageData *packages.Package) cdx.Component {
	if packageData.NormalizedLicenses != nil {
		if len(packageData.NormalizedLicenses) > 0 {
			expression := packageData.NormalizedLicenses[0]
			licences := cdx.LicenseChoice{Expression: expression}
			component.Licenses = &cdx.Licenses{licences}
		}
	}
	return component
}

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
					component = enrichDescription(component, packageData)
					component = enrichLicense(component, packageData)
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
