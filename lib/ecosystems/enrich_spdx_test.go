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
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/rs/zerolog"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/parlay/lib/sbom"
)

func parseJson(t *testing.T, jsonStr string) map[string]any {
	t.Helper()
	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &result))
	return result
}

func setupHttpmock(t *testing.T, packageVersionsResponse, packageResponse *string) {
	t.Helper()
	httpmock.Activate()

	if packageVersionsResponse != nil {
		httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries/.*/packages/.*/versions`,
			func(r *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, parseJson(t, *packageVersionsResponse))
			},
		)
	}

	if packageResponse != nil {
		httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
			func(req *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, parseJson(t, *packageResponse))
			})
	}
}

func TestEnrichSBOM_SPDX(t *testing.T) {
	packageVersionResponse := `{
		"licenses": "MIT"
	}`
	packageResponse := `{
		"description": "description",
		"normalized_licenses": ["BSD-3-Clause"],
		"homepage": "https://github.com/spdx/tools-golang",
		"repo_metadata": {
			"owner_record": {
				"name": "Acme Corp"
			}
		}
	}`
	setupHttpmock(t, &packageVersionResponse, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)

	bom, ok := doc.BOM.(*v2_3.Document)
	require.True(t, ok)

	bom.Packages = []*v2_3.Package{
		{
			PackageSPDXIdentifier: "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
			PackageName:           "github.com/spdx/tools-golang",
			PackageVersion:        "v0.5.2",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
				},
			},
		},
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	pkgs := bom.Packages

	assert.Equal(t, "description", pkgs[0].PackageDescription)
	assert.Equal(t, "MIT", pkgs[0].PackageLicenseConcluded)
	assert.Equal(t, "https://github.com/spdx/tools-golang", pkgs[0].PackageHomePage)
	assert.Equal(t, "Organization", pkgs[0].PackageSupplier.SupplierType)
	assert.Equal(t, "Acme Corp", pkgs[0].PackageSupplier.Supplier)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, len(pkgs), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])

	buf := bytes.NewBuffer(nil)
	require.NoError(t, doc.Encode(buf))
}

func TestEnrichSBOM_SPDX_WithDuplicates(t *testing.T) {
	packageVersionResponse := `{
		"licenses": "MIT"
	}`
	packageResponse := `{
		"description": "description",
		"normalized_licenses": ["BSD-3-Clause"],
		"homepage": "https://github.com/spdx/tools-golang",
		"repo_metadata": {
			"owner_record": {
				"name": "Acme Corp"
			}
		}
	}`
	setupHttpmock(t, &packageVersionResponse, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)

	bom, ok := doc.BOM.(*v2_3.Document)
	require.True(t, ok)

	// Create SBOM with duplicate packages to test caching
	bom.Packages = []*v2_3.Package{
		{
			PackageSPDXIdentifier: "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
			PackageName:           "github.com/spdx/tools-golang",
			PackageVersion:        "v0.5.2",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
				},
			},
		},
		{
			PackageSPDXIdentifier: "pkg:golang/github.com/spdx/tools-golang@v0.5.2-duplicate",
			PackageName:           "github.com/spdx/tools-golang",
			PackageVersion:        "v0.5.2",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
				},
			},
		},
		{
			PackageSPDXIdentifier: "pkg:npm/lodash@4.17.21",
			PackageName:           "lodash",
			PackageVersion:        "4.17.21",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:npm/lodash@4.17.21",
				},
			},
		},
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	pkgs := bom.Packages

	// Verify both duplicate packages are enriched correctly
	assert.Equal(t, "description", pkgs[0].PackageDescription)
	assert.Equal(t, "MIT", pkgs[0].PackageLicenseConcluded)
	assert.Equal(t, "https://github.com/spdx/tools-golang", pkgs[0].PackageHomePage)
	assert.Equal(t, "Organization", pkgs[0].PackageSupplier.SupplierType)
	assert.Equal(t, "Acme Corp", pkgs[0].PackageSupplier.Supplier)

	assert.Equal(t, "description", pkgs[1].PackageDescription)
	assert.Equal(t, "MIT", pkgs[1].PackageLicenseConcluded)
	assert.Equal(t, "https://github.com/spdx/tools-golang", pkgs[1].PackageHomePage)
	assert.Equal(t, "Organization", pkgs[1].PackageSupplier.SupplierType)
	assert.Equal(t, "Acme Corp", pkgs[1].PackageSupplier.Supplier)

	// Verify caching worked: should have made only 4 API calls instead of 6
	// (2 calls for unique golang package + 2 calls for unique npm package)
	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	packageCalls := calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`]
	versionCalls := calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries/.*/packages/.*/versions`]
	totalCalls := packageCalls + versionCalls
	// Without caching, it would make 6 calls (3 packages * 2 calls each)
	// With caching, it should make 4 calls (2 unique packages * 2 calls each)
	assert.Equal(t, 4, totalCalls)
}

func TestEnrichSBOM_MissingVersionedLicense(t *testing.T) {
	packageVersionResponse := `{
		"licenses": ""
	}`
	packageResponse := `{
		"description": "description",
		"normalized_licenses": ["BSD-3-Clause", "Apache-2.0"],
		"homepage": "https://github.com/spdx/tools-golang",
		"repo_metadata": {
			"owner_record": {
				"name": "Acme Corp"
			}
		}
	}`
	setupHttpmock(t, &packageVersionResponse, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)

	bom, ok := doc.BOM.(*v2_3.Document)
	require.True(t, ok)

	bom.Packages = []*v2_3.Package{
		{
			PackageSPDXIdentifier: "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
			PackageName:           "github.com/spdx/tools-golang",
			PackageVersion:        "v0.5.2",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
				},
			},
		},
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	pkgs := bom.Packages

	assert.Equal(t, "description", pkgs[0].PackageDescription)
	assert.Equal(t, "BSD-3-Clause,Apache-2.0", pkgs[0].PackageLicenseConcluded)
	assert.Equal(t, "https://github.com/spdx/tools-golang", pkgs[0].PackageHomePage)
	assert.Equal(t, "Organization", pkgs[0].PackageSupplier.SupplierType)
	assert.Equal(t, "Acme Corp", pkgs[0].PackageSupplier.Supplier)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, len(pkgs), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])

	buf := bytes.NewBuffer(nil)
	require.NoError(t, doc.Encode(buf))
}

func TestEnrichSBOM_SPDX_NoSupplierName(t *testing.T) {
	packageResponse := `{
		"description": "description",
		"normalized_licenses": ["BSD-3-Clause"],
		"homepage": "https://github.com/spdx/tools-golang",
		"repo_metadata": {
			"owner_record": {
				"name": ""
			}
		}
	}`
	setupHttpmock(t, nil, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)

	bom, ok := doc.BOM.(*v2_3.Document)
	require.True(t, ok)

	bom.Packages = []*v2_3.Package{
		{
			PackageSPDXIdentifier: "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
			PackageName:           "github.com/spdx/tools-golang",
			PackageVersion:        "v0.5.2",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:golang/github.com/spdx/tools-golang@v0.5.2",
				},
			},
		},
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, doc.Encode(buf))
}
