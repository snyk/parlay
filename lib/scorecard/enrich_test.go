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

package scorecard

import (
	"errors"
	"net/http"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jarcoal/httpmock"
	"github.com/spdx/tools-golang/spdx"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/parlay/lib/sbom"
)

const scorecardURL = "https://api.securityscorecards.dev/projects/example.com/repository"

func TestEnrichSBOM_CycloneDX(t *testing.T) {
	teardown := setupEcosystemsAPIMock(t)
	defer teardown()

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				PackageURL: "pkg:/example",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	EnrichSBOM(doc)

	assert.NotNil(t, bom.Components)
	assert.Len(t, *bom.Components, 1)

	enrichedComponent := (*bom.Components)[0]
	assert.NotNil(t, enrichedComponent.ExternalReferences)
	assert.Len(t, *enrichedComponent.ExternalReferences, 1)
	assert.Equal(t, scorecardURL, (*enrichedComponent.ExternalReferences)[0].URL)
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

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				PackageURL: "pkg:/example",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	EnrichSBOM(doc)

	assert.NotNil(t, bom.Components)
	assert.Len(t, *bom.Components, 1)

	enrichedComponent := (*bom.Components)[0]
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

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				PackageURL: "pkg:/example",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	EnrichSBOM(doc)

	assert.NotNil(t, bom.Components)
	assert.Len(t, *bom.Components, 1)

	enrichedComponent := (*bom.Components)[0]
	assert.Nil(t, enrichedComponent.ExternalReferences)
}

func TestEnrichSBOM_SPDX(t *testing.T) {
	teardown := setupEcosystemsAPIMock(t)
	defer teardown()

	bom := &spdx.Document{
		Packages: []*spdx_2_3.Package{
			{
				PackageExternalReferences: []*spdx_2_3.PackageExternalReference{
					{
						Category: "OTHER",
						RefType:  "purl",
						Locator:  "pkg:golang/snyk/parlay",
					},
				},
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	EnrichSBOM(doc)

	pkg := bom.Packages[0]
	assert.NotNil(t, pkg.PackageExternalReferences)
	assert.Len(t, pkg.PackageExternalReferences, 2)

	scRef := pkg.PackageExternalReferences[1]
	assert.Equal(t, scorecardURL, scRef.Locator)
	assert.Equal(t, "openssfscorecard", scRef.RefType)
	assert.Equal(t, "OTHER", scRef.Category)
}

func setupEcosystemsAPIMock(t *testing.T) func() {
	t.Helper()

	httpmock.Activate()
	httpmock.RegisterResponder(
		"GET",
		"=~^https://packages.ecosyste.ms/api/v1/registries",
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"repository_url": "https://example.com/repository",
			})
		},
	)
	httpmock.RegisterResponder(
		"GET",
		scorecardURL,
		httpmock.NewStringResponder(http.StatusOK, "{}"),
	)
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected HTTP request: " + req.URL.String())
	})

	return httpmock.DeactivateAndReset
}
