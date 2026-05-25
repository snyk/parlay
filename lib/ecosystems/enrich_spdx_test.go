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
	"fmt"
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

func TestEnrichSBOM_MissingVersionedLicense(t *testing.T) {
	ResetGlobalCache()
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

func TestEnrichSBOM_SPDX_MultiplePackages(t *testing.T) {
	ResetGlobalCache()
	packageVersionResponse := `{
		"licenses": "MIT"
	}`
	packageResponse := `{
		"description": "a package",
		"normalized_licenses": ["MIT"],
		"homepage": "https://github.com/example/pkg",
		"repo_metadata": {
			"owner_record": {
				"name": "Example Org"
			}
		}
	}`
	setupHttpmock(t, &packageVersionResponse, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)

	bom, ok := doc.BOM.(*v2_3.Document)
	require.True(t, ok)

	// Create 50 packages to exercise concurrent processing
	bom.Packages = make([]*v2_3.Package, 50)
	for i := range bom.Packages {
		bom.Packages[i] = &v2_3.Package{
			PackageSPDXIdentifier: common.ElementID(fmt.Sprintf("SPDXRef-pkg%d", i)),
			PackageName:           fmt.Sprintf("github.com/example/pkg%d", i),
			PackageVersion:        "v1.0.0",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  fmt.Sprintf("pkg:golang/github.com/example/pkg%d@v1.0.0", i),
				},
			},
		}
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	// Verify all packages were enriched
	for i, pkg := range bom.Packages {
		assert.Equal(t, "a package", pkg.PackageDescription, "package %d description", i)
		assert.Equal(t, "https://github.com/example/pkg", pkg.PackageHomePage, "package %d homepage", i)
		assert.Equal(t, "MIT", pkg.PackageLicenseConcluded, "package %d license", i)
		assert.Equal(t, "Organization", pkg.PackageSupplier.SupplierType, "package %d supplier type", i)
		assert.Equal(t, "Example Org", pkg.PackageSupplier.Supplier, "package %d supplier", i)
	}

	buf := bytes.NewBuffer(nil)
	require.NoError(t, doc.Encode(buf))
}

func TestEnrichSBOM_SPDX_PackagesWithoutPurl(t *testing.T) {
	ResetGlobalCache()
	packageVersionResponse := `{
		"licenses": "Apache-2.0"
	}`
	packageResponse := `{
		"description": "enriched",
		"homepage": "https://github.com/example/valid",
		"repo_metadata": {}
	}`
	setupHttpmock(t, &packageVersionResponse, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)

	bom, ok := doc.BOM.(*v2_3.Document)
	require.True(t, ok)

	bom.Packages = []*v2_3.Package{
		{
			PackageSPDXIdentifier: "SPDXRef-valid",
			PackageName:           "github.com/example/valid",
			PackageVersion:        "v1.0.0",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:golang/github.com/example/valid@v1.0.0",
				},
			},
		},
		{
			// Package without any external references (no purl)
			PackageSPDXIdentifier: "SPDXRef-nopurl",
			PackageName:           "internal-package",
			PackageVersion:        "0.0.1",
		},
		{
			PackageSPDXIdentifier: "SPDXRef-valid2",
			PackageName:           "github.com/example/valid2",
			PackageVersion:        "v2.0.0",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: common.CategoryPackageManager,
					RefType:  "purl",
					Locator:  "pkg:golang/github.com/example/valid2@v2.0.0",
				},
			},
		},
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	// Valid packages should be enriched
	assert.Equal(t, "enriched", bom.Packages[0].PackageDescription)
	assert.Equal(t, "https://github.com/example/valid", bom.Packages[0].PackageHomePage)
	assert.Equal(t, "Apache-2.0", bom.Packages[0].PackageLicenseConcluded)

	// Package without purl should be untouched
	assert.Equal(t, "", bom.Packages[1].PackageDescription)
	assert.Equal(t, "", bom.Packages[1].PackageHomePage)
	assert.Equal(t, "", bom.Packages[1].PackageLicenseConcluded)

	// Second valid package should also be enriched
	assert.Equal(t, "enriched", bom.Packages[2].PackageDescription)
	assert.Equal(t, "https://github.com/example/valid", bom.Packages[2].PackageHomePage)
	assert.Equal(t, "Apache-2.0", bom.Packages[2].PackageLicenseConcluded)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, doc.Encode(buf))
}
