package lib

import (
	"net/http"
	"testing"

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

	/*
		components = *bom.Components
		component := components[0]
	  licenses := *component.Licenses

		comp := cdx.LicenseChoice(cdx.LicenseChoice{Expression: "BSD-3-Clause"})

		assert.Equal(t, "description", components[0].Description)
		assert.Equal(t, comp, licenses[0])

		httpmock.GetTotalCallCount()
		calls := httpmock.GetCallCountInfo()
		assert.Equal(t, len(components), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
	*/
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
