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
	"net/url"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/zerolog"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/internal/utils"
)

type cdxPackageEnricher = func(*cdx.Component, *packages.Package)
type cdxPackageVersionEnricher = func(*cdx.Component, *packages.Version)

var cdxPackageEnrichers = []cdxPackageEnricher{
	enrichCDXDescription,
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

var cdxPackageVersionEnrichers = []cdxPackageVersionEnricher{
	enrichCDXLicense,
}

func enrichCDXDescription(comp *cdx.Component, data *packages.Package) {
	if data.Description != nil {
		comp.Description = *data.Description
	}
}

func enrichCDXLicense(comp *cdx.Component, data *packages.Version) {
	validLics, invalidLics := utils.GetSPDXLicensesFromEcosystemsLicense(data)
	var licenses cdx.Licenses
	for _, licenseID := range validLics {
		license := cdx.License{ID: licenseID}
		licenses = append(licenses, cdx.LicenseChoice{License: &license})
	}
	for _, licenseName := range invalidLics {
		license := cdx.License{Name: licenseName}
		licenses = append(licenses, cdx.LicenseChoice{License: &license})
	}
	comp.Licenses = &licenses
}

func enrichExternalReference(comp *cdx.Component, ref *string, refType cdx.ExternalReferenceType) {
	if ref == nil {
		return
	}
	if _, err := url.Parse(*ref); err != nil {
		return
	}
	ext := cdx.ExternalReference{
		URL:  *ref,
		Type: refType,
	}
	if comp.ExternalReferences == nil {
		comp.ExternalReferences = &[]cdx.ExternalReference{ext}
	} else {
		*comp.ExternalReferences = append(*comp.ExternalReferences, ext)
	}
}

func enrichProperty(comp *cdx.Component, name string, value string) {
	prop := cdx.Property{
		Name:  name,
		Value: value,
	}
	if comp.Properties == nil {
		comp.Properties = &[]cdx.Property{prop}
	} else {
		*comp.Properties = append(*comp.Properties, prop)
	}
}

func enrichCDXHomepage(comp *cdx.Component, data *packages.Package) {
	enrichExternalReference(comp, data.Homepage, cdx.ERTypeWebsite)
}

func enrichCDXRegistryURL(comp *cdx.Component, data *packages.Package) {
	enrichExternalReference(comp, data.RegistryUrl, cdx.ERTypeDistribution)
}

func enrichCDXRepositoryURL(comp *cdx.Component, data *packages.Package) {
	enrichExternalReference(comp, data.RepositoryUrl, cdx.ERTypeVCS)
}

func enrichCDXDocumentationURL(comp *cdx.Component, data *packages.Package) {
	enrichExternalReference(comp, data.DocumentationUrl, cdx.ERTypeDocumentation)
}

func enrichCDXFirstReleasePublishedAt(comp *cdx.Component, data *packages.Package) {
	if data.FirstReleasePublishedAt == nil {
		return
	}
	timestamp := data.FirstReleasePublishedAt.UTC().Format(time.RFC3339)
	enrichProperty(comp, "ecosystems:first_release_published_at", timestamp)
}

func enrichCDXLatestReleasePublishedAt(comp *cdx.Component, data *packages.Package) {
	if data.LatestReleasePublishedAt == nil {
		return
	}
	timestamp := data.LatestReleasePublishedAt.UTC().Format(time.RFC3339)
	enrichProperty(comp, "ecosystems:latest_release_published_at", timestamp)
}

func enrichCDXRepoArchived(comp *cdx.Component, data *packages.Package) {
	if data.RepoMetadata != nil {
		if archived, ok := (*data.RepoMetadata)["archived"].(bool); ok && archived {
			enrichProperty(comp, "ecosystems:repository_archived", "true")
		}
	}
}

func enrichCDXLocation(comp *cdx.Component, data *packages.Package) {
	if data.RepoMetadata != nil {
		meta := *data.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if location, ok := ownerRecord["location"].(string); ok {
				enrichProperty(comp, "ecosystems:owner_location", location)
			}
		}
	}
}

func enrichCDXAuthor(comp *cdx.Component, data *packages.Package) {
	if data.RepoMetadata != nil {
		meta := *data.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if name, ok := ownerRecord["name"].(string); ok {
				comp.Author = name
			}
		}
	}
}

func enrichCDXSupplier(comp *cdx.Component, data *packages.Package) {
	if data.RepoMetadata != nil {
		meta := *data.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if name, ok := ownerRecord["name"].(string); ok {
				supplier := cdx.OrganizationalEntity{
					Name: name,
				}
				if website, ok := ownerRecord["website"].(string); ok {
					split := strings.Split(website, ", ")
					for i := range split {
						split[i] = strings.TrimSpace(split[i])
					}
					supplier.URL = &split
				}
				comp.Supplier = &supplier
			}
		}
	}
}

func enrichCDXTopics(comp *cdx.Component, data *packages.Package) {
	if data.RepoMetadata != nil {
		meta := *data.RepoMetadata

		if topics, ok := meta["topics"].([]interface{}); ok {
			for _, topic := range topics {
				if s, ok := topic.(string); ok {
					enrichProperty(comp, "ecosystems:topic", s)
				}
			}
		}
	}
}

func enrichCDX(bom *cdx.BOM, logger *zerolog.Logger) {
	wg := sizedwaitgroup.New(20)

	comps := utils.DiscoverCDXComponents(bom)
	logger.Debug().Msgf("Detected %d packages", len(comps))

	for i := range comps {
		wg.Add()
		go func(comp *cdx.Component) {
			defer wg.Done()
			l := logger.With().Str("bom-ref", comp.BOMRef).Logger()

			purl, err := packageurl.FromString(comp.PackageURL)
			if err != nil {
				l.Debug().
					Err(err).
					Msg("Skipping package: no usable PackageURL")
				return
			}

			packageResp, err := GetPackageData(purl)
			if err != nil {
				l.Debug().
					Err(err).
					Msg("Skipping package: failed to get package data")
				return
			}

			if packageResp.JSON200 == nil {
				l.Debug().
					Err(err).
					Msg("Skipping package: no data on ecosyste.ms response")
				return
			}

			for _, enrichFunc := range cdxPackageEnrichers {
				enrichFunc(comp, packageResp.JSON200)
			}

			packageVersionResp, err := GetPackageVersionData(purl)
			if err != nil {
				l.Debug().
					Err(err).
					Msg("Skipping package version enrichment: failed to get package version data")
				return
			}

			if packageVersionResp.JSON200 == nil {
				l.Debug().
					Err(err).
					Msg("Skipping package version enrichment: no data on ecosyste.ms response")
				return
			}

			for _, enrichFunc := range cdxPackageVersionEnrichers {
				enrichFunc(comp, packageVersionResp.JSON200)
			}

		}(comps[i])
	}

	wg.Wait()
}
