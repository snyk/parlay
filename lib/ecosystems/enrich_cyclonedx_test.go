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
	"net/http"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jarcoal/httpmock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/lib/sbom"
)

func TestEnrichSBOM_CycloneDX(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries/.*/packages/.*/versions`,
		func(r *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				// This is the license we expect to see for the specific package version
				"licenses": "MIT",
			})
		},
	)
	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"description": "description",
				"normalized_licenses": []string{
					// This license should be ignored as it corresponds to the latest version of the package
					"BSD-3-Clause",
				},
			})
		})

	bom := &cdx.BOM{
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef:     "pkg:golang/github.com/ACME/Project@v1.0.0",
				Type:       cdx.ComponentTypeApplication,
				Name:       "Project",
				Version:    "v1.0.0",
				PackageURL: "pkg:golang/github.com/ACME/Project@v1.0.0",
			},
		},
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "cyclonedx-go",
				Version:    "v0.3.0",
				PackageURL: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	components := *bom.Components
	component := components[0]
	licenses := *component.Licenses

	comp := cdx.LicenseChoice(cdx.LicenseChoice{Expression: "(MIT)"})

	assert.Equal(t, "description", components[0].Description)
	assert.Equal(t, comp, licenses[0])

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, 2, calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
}

func TestEnrichSBOM_CycloneDX_NestedComps(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{})
		})

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "@emotion/babel-plugin@11.11.0",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "babel-plugin",
				Version:    "v11.11.0",
				PackageURL: "pkg:npm/%40emotion/babel-plugin@11.11.0",
				Components: &[]cdx.Component{
					{
						Type:       cdx.ComponentTypeLibrary,
						Name:       "convert-source-map",
						Version:    "v1.9.0",
						BOMRef:     "@emotion/babel-plugin@11.11.0|convert-source-map@1.9.0",
						PackageURL: "pkg:npm/convert-source-map@1.9.0",
					},
				},
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, 4, calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
}

func TestEnrichSBOMWithoutLicense(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"description":         "description",
				"normalized_licenses": []string{},
			})
		})

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
				Type:       cdx.ComponentTypeLibrary,
				Name:       "cyclonedx-go",
				Version:    "v0.3.0",
				PackageURL: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	components := *bom.Components

	assert.Equal(t, "description", components[0].Description)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, 2*len(components), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
}

func TestEnrichDescription(t *testing.T) {
	component := &cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "cyclonedx-go",
		Version: "v0.3.0",
	}
	desc := "description"
	pack := &packages.Package{
		Description: &desc,
	}

	enrichCDXDescription(component, pack)

	assert.Equal(t, "description", component.Description)
}

func TestEnrichLicense(t *testing.T) {
	component := &cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "cyclonedx-go",
		Version: "v0.3.0",
	}
	versionedLicenses := "BSD-3-Clause"
	pkgVersionData := &packages.VersionWithDependencies{Licenses: &versionedLicenses}
	latestLicenses := []string{"Apache-2.0"}
	pkgData := &packages.Package{NormalizedLicenses: latestLicenses}

	enrichCDXLicense(component, pkgVersionData, pkgData)

	licenses := *component.Licenses
	comp := cdx.LicenseChoice(cdx.LicenseChoice{Expression: "(BSD-3-Clause)"})
	assert.Equal(t, 1, len(licenses))
	assert.Equal(t, comp, licenses[0])
}

func TestEnrichLicenseNoVersionedLicense(t *testing.T) {
	component := &cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "cyclonedx-go",
		Version: "v0.3.0",
	}
	versionedLicenses := ""
	pkgVersionData := &packages.VersionWithDependencies{Licenses: &versionedLicenses}
	latestLicenses := []string{"Apache-2.0"}
	pkgData := &packages.Package{NormalizedLicenses: latestLicenses}

	enrichCDXLicense(component, pkgVersionData, pkgData)

	licenses := *component.Licenses
	comp := cdx.LicenseChoice(cdx.LicenseChoice{Expression: "(Apache-2.0)"})
	assert.Equal(t, 1, len(licenses))
	assert.Equal(t, comp, licenses[0])
}

func TestEnrichLicenseNoLatestLicense(t *testing.T) {
	component := &cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "cyclonedx-go",
		Version: "v0.3.0",
	}
	versionedLicenses := "BSD-3-Clause"
	pkgVersionData := &packages.VersionWithDependencies{Licenses: &versionedLicenses}
	latestLicenses := []string{""}
	pkgData := &packages.Package{NormalizedLicenses: latestLicenses}

	enrichCDXLicense(component, pkgVersionData, pkgData)

	licenses := *component.Licenses
	comp := cdx.LicenseChoice(cdx.LicenseChoice{Expression: "(BSD-3-Clause)"})
	assert.Equal(t, 1, len(licenses))
	assert.Equal(t, comp, licenses[0])
}

func TestEnrichBlankSBOM(t *testing.T) {
	bom := new(cdx.BOM)
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	assert.Nil(t, bom.Components)
}

func TestEnrichExternalReferenceWithNilURL(t *testing.T) {
	component := &cdx.Component{}
	packageData := &packages.Package{Homepage: nil}

	enrichExternalReference(component, packageData.Homepage, cdx.ERTypeWebsite)

	assert.Nil(t, component.ExternalReferences)
}

func TestEnrichExternalReferenceWithNonNullURL(t *testing.T) {
	component := &cdx.Component{}
	packageData := packages.Package{Homepage: pointerToString(t, "https://example.com")}

	enrichExternalReference(component, packageData.Homepage, cdx.ERTypeWebsite)

	expected := &[]cdx.ExternalReference{
		{URL: "https://example.com", Type: cdx.ERTypeWebsite},
	}
	assert.Equal(t, expected, component.ExternalReferences)
}

func TestEnrichHomepageWithNilHomepage(t *testing.T) {
	component := &cdx.Component{}
	packageData := &packages.Package{Homepage: nil}

	enrichCDXHomepage(component, packageData)

	assert.Nil(t, component.ExternalReferences)
}

func TestEnrichHomepageWithNonNullHomepage(t *testing.T) {
	component := &cdx.Component{}
	packageData := &packages.Package{Homepage: pointerToString(t, "https://example.com")}

	enrichCDXHomepage(component, packageData)

	expected := &[]cdx.ExternalReference{
		{URL: "https://example.com", Type: cdx.ERTypeWebsite},
	}
	assert.Equal(t, expected, component.ExternalReferences)
}

func TestEnrichRegistryURLWithNilRegistryURL(t *testing.T) {
	component := &cdx.Component{}
	packageData := &packages.Package{RegistryUrl: nil}

	enrichCDXRegistryURL(component, packageData)

	assert.Nil(t, component.ExternalReferences)
}

func TestEnrichRegistryURLWithNonNullRegistryURL(t *testing.T) {
	component := &cdx.Component{}
	packageData := &packages.Package{RegistryUrl: pointerToString(t, "https://example.com")}

	enrichCDXRegistryURL(component, packageData)

	expected := &[]cdx.ExternalReference{
		{URL: "https://example.com", Type: cdx.ERTypeDistribution},
	}
	assert.Equal(t, expected, component.ExternalReferences)
}

func pointerToString(t *testing.T, s string) *string {
	t.Helper()
	return &s
}

func TestEnrichLatestReleasePublishedAt(t *testing.T) {
	component := &cdx.Component{}
	packageData := &packages.Package{
		LatestReleasePublishedAt: nil,
	}

	enrichCDXLatestReleasePublishedAt(component, packageData)

	assert.Nil(t, component.Properties)

	latestReleasePublishedAt := time.Date(2023, time.May, 1, 0, 0, 0, 0, time.UTC)
	packageData.LatestReleasePublishedAt = &latestReleasePublishedAt
	expectedTimestamp := latestReleasePublishedAt.UTC().Format(time.RFC3339)

	enrichCDXLatestReleasePublishedAt(component, packageData)

	assert.Len(t, *component.Properties, 1)
	prop := (*component.Properties)[0]
	assert.Equal(t, "ecosystems:latest_release_published_at", prop.Name)
	assert.Equal(t, expectedTimestamp, prop.Value)
}

func TestEnrichLocation(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: packageData.RepoMetadata is nil
	component := &cdx.Component{Name: "test"}
	packageData := &packages.Package{}
	enrichCDXLocation(component, packageData)
	assert.Nil(component.Properties)

	// Test case 2: packageData.RepoMetadata is not nil, but "owner_record" is missing
	component = &cdx.Component{Name: "test"}
	packageData = &packages.Package{RepoMetadata: &map[string]interface{}{
		"not_owner_record": map[string]interface{}{},
	}}
	enrichCDXLocation(component, packageData)
	assert.Nil(component.Properties)

	// Test case 3: "location" field is missing in "owner_record"
	component = &cdx.Component{Name: "test"}
	packageData = &packages.Package{RepoMetadata: &map[string]interface{}{
		"owner_record": map[string]interface{}{
			"not_location": "test",
		},
	}}
	enrichCDXLocation(component, packageData)
	assert.Nil(component.Properties)

	// Test case 4: "location" field is present in "owner_record"
	component = &cdx.Component{Name: "test"}
	packageData = &packages.Package{RepoMetadata: &map[string]interface{}{
		"owner_record": map[string]interface{}{
			"location": "test_location",
		},
	}}
	enrichCDXLocation(component, packageData)
	assert.Equal(&[]cdx.Property{
		{Name: "ecosystems:owner_location", Value: "test_location"},
	}, component.Properties)
}
