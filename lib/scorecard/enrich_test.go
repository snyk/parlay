package scorecard

import (
	"errors"
	"net/http"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jarcoal/httpmock"
	"github.com/snyk/parlay/lib/sbom"
	"github.com/stretchr/testify/assert"
)

func TestEnrichSBOM(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"repository_url": "https://example.com/repository",
			})
		})

	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected HTTP request: " + req.URL.String())
	})

	scorecardUrl := "https://api.securityscorecards.dev/projects/example.com/repository"
	httpmock.RegisterResponder("GET", scorecardUrl,
		httpmock.NewStringResponder(http.StatusOK, "{}"))

	doc := &sbom.SBOMDocument{
		BOM: &cdx.BOM{
			Components: &[]cdx.Component{
				{
					PackageURL: "pkg:/example",
				},
			},
		},
	}

	EnrichSBOM(doc)

	enrichedBOM := *doc.BOM

	assert.NotNil(t, enrichedBOM.Components)
	assert.Len(t, *enrichedBOM.Components, 1)

	enrichedComponent := (*enrichedBOM.Components)[0]
	assert.NotNil(t, enrichedComponent.ExternalReferences)
	assert.Len(t, *enrichedComponent.ExternalReferences, 1)
	assert.Equal(t, scorecardUrl, (*enrichedComponent.ExternalReferences)[0].URL)
	assert.Equal(t, "OpenSSF Scorecard", (*enrichedComponent.ExternalReferences)[0].Comment)
	assert.Equal(t, cdx.ERTypeOther, (*enrichedComponent.ExternalReferences)[0].Type)

	total := httpmock.GetTotalCallCount()
	assert.Equal(t, 2, total)
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
}

func TestEnrichSBOM_ErrorFetchingPackageData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewErrorResponder(assert.AnError))

	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected HTTP request: " + req.URL.String())
	})

	doc := &sbom.SBOMDocument{
		BOM: &cdx.BOM{
			Components: &[]cdx.Component{
				{
					PackageURL: "pkg:/example",
				},
			},
		},
	}

	EnrichSBOM(doc)

	enrichedBOM := *doc.BOM

	assert.NotNil(t, enrichedBOM.Components)
	assert.Len(t, *enrichedBOM.Components, 1)

	enrichedComponent := (*enrichedBOM.Components)[0]
	assert.Nil(t, enrichedComponent.ExternalReferences)
}

func TestEnrichSBOM_ErrorFetchingScorecard(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockPackageData := `{"JSON200": {"RepositoryUrl": "https://example.com/repository"}}`
	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(http.StatusOK, mockPackageData))

	httpmock.RegisterResponder("GET", "https://api.securityscorecards.dev/projects/example.com/repository",
		httpmock.NewErrorResponder(assert.AnError))

	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected HTTP request: " + req.URL.String())
	})

	doc := &sbom.SBOMDocument{
		BOM: &cdx.BOM{
			Components: &[]cdx.Component{
				{
					PackageURL: "pkg:/example",
				},
			},
		},
	}

	EnrichSBOM(doc)

	enrichedBOM := *doc.BOM

	assert.NotNil(t, enrichedBOM.Components)
	assert.Len(t, *enrichedBOM.Components, 1)

	enrichedComponent := (*enrichedBOM.Components)[0]
	assert.Nil(t, enrichedComponent.ExternalReferences)
}
