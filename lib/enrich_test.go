package lib

import (
	"net/http"
	"testing"

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

func TestEnrichBlankSBOM(t *testing.T) {
	bom := new(cdx.BOM)
	bom = EnrichSBOM(bom)
	assert.Nil(t, bom.Components)
}
