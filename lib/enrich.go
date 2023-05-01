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

func enrichExternalReference(component cdx.Component, packageData *packages.Package, url *string, refType cdx.ExternalReferenceType) cdx.Component {
	if url == nil {
		return component
	}
	ext := cdx.ExternalReference{
		URL:  *url,
		Type: refType,
	}
	if component.ExternalReferences == nil {
		component.ExternalReferences = &[]cdx.ExternalReference{ext}
	} else {
		*component.ExternalReferences = append(*component.ExternalReferences, ext)
	}
	return component
}

func enrichHomepage(component cdx.Component, packageData *packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.Homepage, cdx.ERTypeWebsite)
}

func enrichRegistryURL(component cdx.Component, packageData *packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RegistryUrl, cdx.ERTypeDistribution)
}

func enrichRepositoryURL(component cdx.Component, packageData *packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RepositoryUrl, cdx.ERTypeVCS)
}

func enrichDocumentationURL(component cdx.Component, packageData *packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.DocumentationUrl, cdx.ERTypeDocumentation)
}

func enrichComponents(bom *cdx.BOM, enrichFuncs []func(cdx.Component, *packages.Package) cdx.Component) {
	wg := sizedwaitgroup.New(20)
	newComponents := make([]cdx.Component, len(*bom.Components))
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			purl, _ := packageurl.FromString(component.PackageURL)
			resp, err := GetPackageData(purl)
			if err == nil {
				packageData := resp.JSON200
				if packageData != nil {
					for _, enrichFunc := range enrichFuncs {
						component = enrichFunc(component, packageData)
					}
				}
			}
			newComponents[i] = component
			wg.Done()
		}(component, i)
	}
	wg.Wait()
	bom.Components = &newComponents
}

func EnrichSBOM(bom *cdx.BOM) *cdx.BOM {
	if bom.Components == nil {
		return bom
	}

	enrichFuncs := []func(cdx.Component, *packages.Package) cdx.Component{
		enrichDescription,
		enrichLicense,
		enrichHomepage,
		enrichRegistryURL,
		enrichRepositoryURL,
		enrichDocumentationURL,
	}

	enrichComponents(bom, enrichFuncs)
	return bom
}
