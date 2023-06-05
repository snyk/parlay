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

	"github.com/snyk/parlay/ecosystems/packages"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestEnrichSBOM(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"description": "description",
				"normalized_licenses": []string{
					"BSD-3-Clause",
				},
			})
		})

	bom := new(cdx.BOM)

	components := []cdx.Component{
		{
			BOMRef:     "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "cyclonedx-go",
			Version:    "v0.3.0",
			PackageURL: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
		},
	}

	bom.Components = &components

	bom = EnrichSBOM(bom)

	components = *bom.Components
	component := components[0]
	licenses := *component.Licenses

	comp := cdx.LicenseChoice(cdx.LicenseChoice{Expression: "BSD-3-Clause"})

	assert.Equal(t, "description", components[0].Description)
	assert.Equal(t, comp, licenses[0])

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, len(components), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
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

	bom := new(cdx.BOM)

	components := []cdx.Component{
		{
			BOMRef:     "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "cyclonedx-go",
			Version:    "v0.3.0",
			PackageURL: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
		},
	}

	bom.Components = &components

	bom = EnrichSBOM(bom)

	components = *bom.Components

	assert.Equal(t, "description", components[0].Description)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, len(components), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
}

func TestEnrichDescription(t *testing.T) {
	component := cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "cyclonedx-go",
		Version: "v0.3.0",
	}
	desc := "description"
	pack := packages.Package{
		Description: &desc,
	}
	component = enrichDescription(component, pack)
	assert.Equal(t, "description", component.Description)
}

func TestEnrichLicense(t *testing.T) {
	component := cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    "cyclonedx-go",
		Version: "v0.3.0",
	}
	pack := packages.Package{
		NormalizedLicenses: []string{"BSD-3-Clause"},
	}
	component = enrichLicense(component, pack)
	licenses := *component.Licenses

	comp := cdx.LicenseChoice(cdx.LicenseChoice{Expression: "BSD-3-Clause"})
	assert.Equal(t, comp, licenses[0])
}

func TestEnrichBlankSBOM(t *testing.T) {
	bom := new(cdx.BOM)
	bom = EnrichSBOM(bom)
	assert.Nil(t, bom.Components)
}

func TestEnrichExternalReferenceWithNilURL(t *testing.T) {
	component := cdx.Component{}
	packageData := packages.Package{Homepage: nil}

	result := enrichExternalReference(component, packageData, packageData.Homepage, cdx.ERTypeWebsite)

	assert.Equal(t, component, result)
}

func TestEnrichExternalReferenceWithNonNullURL(t *testing.T) {
	component := cdx.Component{}
	packageData := packages.Package{Homepage: pointerToString("https://example.com")}

	result := enrichExternalReference(component, packageData, packageData.Homepage, cdx.ERTypeWebsite)

	expected := cdx.Component{
		ExternalReferences: &[]cdx.ExternalReference{
			{URL: "https://example.com", Type: cdx.ERTypeWebsite},
		},
	}
	assert.Equal(t, expected, result)
}

func TestEnrichHomepageWithNilHomepage(t *testing.T) {
	component := cdx.Component{}
	packageData := packages.Package{Homepage: nil}

	result := enrichHomepage(component, packageData)

	assert.Equal(t, component, result)
}

func TestEnrichHomepageWithNonNullHomepage(t *testing.T) {
	component := cdx.Component{}
	packageData := packages.Package{Homepage: pointerToString("https://example.com")}

	result := enrichHomepage(component, packageData)

	expected := cdx.Component{
		ExternalReferences: &[]cdx.ExternalReference{
			{URL: "https://example.com", Type: cdx.ERTypeWebsite},
		},
	}
	assert.Equal(t, expected, result)
}

func TestEnrichRegistryURLWithNilRegistryURL(t *testing.T) {
	component := cdx.Component{}
	packageData := packages.Package{RegistryUrl: nil}

	result := enrichRegistryURL(component, packageData)

	assert.Equal(t, component, result)
}

func TestEnrichRegistryURLWithNonNullRegistryURL(t *testing.T) {
	component := cdx.Component{}
	packageData := packages.Package{RegistryUrl: pointerToString("https://example.com")}

	result := enrichRegistryURL(component, packageData)

	expected := cdx.Component{
		ExternalReferences: &[]cdx.ExternalReference{
			{URL: "https://example.com", Type: cdx.ERTypeDistribution},
		},
	}
	assert.Equal(t, expected, result)
}

func pointerToString(s string) *string {
	return &s
}

func TestEnrichLatestReleasePublishedAt(t *testing.T) {
	component := cdx.Component{}
	packageData := packages.Package{
		LatestReleasePublishedAt: nil,
	}

	result := enrichLatestReleasePublishedAt(component, packageData)
	assert.Equal(t, component, result)

	latestReleasePublishedAt := time.Date(2023, time.May, 1, 0, 0, 0, 0, time.UTC)
	packageData.LatestReleasePublishedAt = &latestReleasePublishedAt
	expectedTimestamp := latestReleasePublishedAt.UTC().Format(time.RFC3339)
	result = enrichLatestReleasePublishedAt(component, packageData)

	prop := (*result.Properties)[0]
	assert.Equal(t, "ecosystems:latest_release_published_at", prop.Name)
	assert.Equal(t, expectedTimestamp, prop.Value)
}

func TestEnrichLocation(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: packageData.RepoMetadata is nil
	component := cdx.Component{Name: "test"}
	packageData := packages.Package{}
	result := enrichLocation(component, packageData)
	assert.Equal(component, result)

	// Test case 2: packageData.RepoMetadata is not nil, but "owner_record" is missing
	component = cdx.Component{Name: "test"}
	packageData = packages.Package{RepoMetadata: &map[string]interface{}{
		"not_owner_record": map[string]interface{}{},
	}}
	result = enrichLocation(component, packageData)
	assert.Equal(component, result)

	// Test case 3: "location" field is missing in "owner_record"
	component = cdx.Component{Name: "test"}
	packageData = packages.Package{RepoMetadata: &map[string]interface{}{
		"owner_record": map[string]interface{}{
			"not_location": "test",
		},
	}}
	result = enrichLocation(component, packageData)
	assert.Equal(component, result)

	// Test case 4: "location" field is present in "owner_record"
	component = cdx.Component{Name: "test"}
	packageData = packages.Package{RepoMetadata: &map[string]interface{}{
		"owner_record": map[string]interface{}{
			"location": "test_location",
		},
	}}
	expectedComponent := cdx.Component{
		Name: "test",
		Properties: &[]cdx.Property{
			{Name: "ecosystems:owner_location", Value: "test_location"},
		},
	}
	result = enrichLocation(component, packageData)
	assert.Equal(expectedComponent, result)
}
