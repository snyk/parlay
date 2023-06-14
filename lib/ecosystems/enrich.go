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
	"fmt"
	"time"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/lib/sbom"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
)

var enrichFuncs = []func(cdx.Component, packages.Package) cdx.Component{
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

func enrichCDXDoc(bom *cdx.BOM) {
	if bom.Components == nil {
		return
	}

	enrichComponentsWithEcosystems(bom, enrichFuncs)
}

func EnrichSBOM(doc *sbom.SBOMDocument) error {
	switch bom := doc.BOM.(type) {
	case *cdx.BOM:
		enrichCDXDoc(bom)
	case *v2_3.Document:
		enrichSPDXDoc(bom)
	default:
		return fmt.Errorf("cannot enrich BOM of type %T", bom)
	}
	return nil
}
