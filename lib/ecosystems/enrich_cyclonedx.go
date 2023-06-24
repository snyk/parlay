/*
 * © 2023 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ecosystems

import (
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"

	"github.com/snyk/parlay/ecosystems/packages"
)

type cdxEnricher = func(cdx.Component, packages.Package) cdx.Component

var cdxEnrichers = []cdxEnricher{
	enrichCDXDescription,
	enrichCDXLicense,
	enrichCDXHomepage,
	enrichCDXRegistryURL,
	enrichCDXRepositoryURL,
	enrichCDXDocumentationURL,
	enrichCDXFirstReleasePublishedAt,
	enrichCDXLatestReleasePublishedAt,
	enrichCDXRepoArchived,
	enrichCDXLocation,
	enrichCDXTopics,
	enrichCDXAuthor,
	enrichCDXSupplier,
}

func enrichCDXDescription(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.Description != nil {
		component.Description = *packageData.Description
	}
	return component
}

func enrichCDXLicense(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.NormalizedLicenses != nil {
		if len(packageData.NormalizedLicenses) > 0 {
			expression := packageData.NormalizedLicenses[0]
			licenses := cdx.LicenseChoice{Expression: expression}
			component.Licenses = &cdx.Licenses{licenses}
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

func enrichCDXHomepage(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.Homepage, cdx.ERTypeWebsite)
}

func enrichCDXRegistryURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RegistryUrl, cdx.ERTypeDistribution)
}

func enrichCDXRepositoryURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RepositoryUrl, cdx.ERTypeVCS)
}

func enrichCDXDocumentationURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.DocumentationUrl, cdx.ERTypeDocumentation)
}

func enrichCDXFirstReleasePublishedAt(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.FirstReleasePublishedAt == nil {
		return component
	}
	timestamp := packageData.FirstReleasePublishedAt.UTC().Format(time.RFC3339)
	return enrichProperty(component, "ecosystems:first_release_published_at", timestamp)
}

func enrichCDXLatestReleasePublishedAt(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.LatestReleasePublishedAt == nil {
		return component
	}
	timestamp := packageData.LatestReleasePublishedAt.UTC().Format(time.RFC3339)
	return enrichProperty(component, "ecosystems:latest_release_published_at", timestamp)
}

func enrichCDXRepoArchived(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		if archived, ok := (*packageData.RepoMetadata)["archived"].(bool); ok && archived {
			return enrichProperty(component, "ecosystems:repository_archived", "true")
		}
	}
	return component
}

func enrichCDXLocation(component cdx.Component, packageData packages.Package) cdx.Component {
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

func enrichCDXAuthor(component cdx.Component, packageData packages.Package) cdx.Component {
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

func enrichCDXSupplier(component cdx.Component, packageData packages.Package) cdx.Component {
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

func enrichCDXTopics(component cdx.Component, packageData packages.Package) cdx.Component {
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

func enrichCDX(bom *cdx.BOM) {
	if bom.Components == nil {
		return
	}

	wg := sizedwaitgroup.New(20)
	newComponents := make([]cdx.Component, len(*bom.Components))
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			// TODO: return when there is no usable Purl on the component.
			purl, _ := packageurl.FromString(component.PackageURL) //nolint:errcheck
			resp, err := GetPackageData(purl)
			if err == nil {
				packageData := resp.JSON200
				if packageData != nil {
					for _, enrichFunc := range cdxEnrichers {
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
