package ecosystems

import (
	"time"

	"github.com/snyk/parlay/ecosystems/packages"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
)

func enrichDescription(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.Description != nil {
		component.Description = *packageData.Description
	}
	return component
}

func enrichLicense(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.NormalizedLicenses != nil {
		if len(packageData.NormalizedLicenses) > 0 {
			expression := packageData.NormalizedLicenses[0]
			licences := cdx.LicenseChoice{Expression: expression}
			component.Licenses = &cdx.Licenses{licences}
		}
	}
	return component
}

func enrichExternalReference(component cdx.Component, packageData packages.Package, url *string, refType cdx.ExternalReferenceType) cdx.Component {
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

func enrichProperty(component cdx.Component, name string, value string) cdx.Component {
	prop := cdx.Property{
		Name:  name,
		Value: value,
	}
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{prop}
	} else {
		*component.Properties = append(*component.Properties, prop)
	}
	return component
}

func enrichHomepage(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.Homepage, cdx.ERTypeWebsite)
}

func enrichRegistryURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RegistryUrl, cdx.ERTypeDistribution)
}

func enrichRepositoryURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RepositoryUrl, cdx.ERTypeVCS)
}

func enrichDocumentationURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.DocumentationUrl, cdx.ERTypeDocumentation)
}

func enrichFirstReleasePublishedAt(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.FirstReleasePublishedAt == nil {
		return component
	}
	timestamp := packageData.FirstReleasePublishedAt.UTC().Format(time.RFC3339)
	return enrichProperty(component, "ecosystems:first_release_published_at", timestamp)
}

func enrichLatestReleasePublishedAt(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.LatestReleasePublishedAt == nil {
		return component
	}
	timestamp := packageData.LatestReleasePublishedAt.UTC().Format(time.RFC3339)
	return enrichProperty(component, "ecosystems:latest_release_published_at", timestamp)
}

func enrichRepoArchived(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		if archived, ok := (*packageData.RepoMetadata)["archived"].(bool); ok && archived {
			return enrichProperty(component, "ecosystems:repository_archived", "true")
		}
	}
	return component
}

func enrichLocation(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if location, ok := ownerRecord["location"].(string); ok {
				return enrichProperty(component, "ecosystems:owner_location", location)
			}
		}
	}
	return component
}

func enrichAuthor(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if name, ok := ownerRecord["name"].(string); ok {
				component.Author = name
				return component
			}
		}
	}
	return component
}

func enrichSupplier(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if name, ok := ownerRecord["name"].(string); ok {
				supplier := cdx.OrganizationalEntity{
					Name: name,
				}
				if website, ok := ownerRecord["website"].(string); ok {
					websites := []string{website}
					supplier.URL = &websites
				}
				component.Supplier = &supplier
				return component
			}
		}
	}
	return component
}

func enrichTopics(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata

		if topics, ok := meta["topics"].([]interface{}); ok {
			for _, topic := range topics {
				component = enrichProperty(component, "ecosystems:topic", topic.(string))
			}
		}
		return component
	}
	return component
}

func enrichComponentsWithEcosystems(bom *cdx.BOM, enrichFuncs []func(cdx.Component, packages.Package) cdx.Component) {
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
						component = enrichFunc(component, *packageData)
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

	enrichFuncs := []func(cdx.Component, packages.Package) cdx.Component{
		enrichDescription,
		enrichLicense,
		enrichHomepage,
		enrichRegistryURL,
		enrichRepositoryURL,
		enrichDocumentationURL,
		enrichFirstReleasePublishedAt,
		enrichLatestReleasePublishedAt,
		enrichRepoArchived,
		enrichLocation,
		enrichTopics,
		enrichAuthor,
		enrichSupplier,
	}

	enrichComponentsWithEcosystems(bom, enrichFuncs)
	return bom
}
