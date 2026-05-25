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

	"github.com/snyk/parlay/ecosystems/packages"
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

func TestEnrichSPDXHash_AppendsParsedIntegrity(t *testing.T) {
	pkg := &v2_3.Package{}
	integrity := "sha256-17ea4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631"
	logger := zerolog.Nop()

	enrichSPDXHash(pkg, &packages.VersionWithDependencies{Integrity: &integrity}, &logger)

	assert.Equal(t, []common.Checksum{
		{
			Algorithm: common.SHA256,
			Value:     "17ea4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631",
		},
	}, pkg.PackageChecksums)
}

func TestEnrichSPDXHash_AppendsToExistingChecksums(t *testing.T) {
	existing := common.Checksum{Algorithm: common.SHA1, Value: "0000000000000000000000000000000000000000"}
	pkg := &v2_3.Package{PackageChecksums: []common.Checksum{existing}}
	integrity := "sha256-17ea4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631"
	logger := zerolog.Nop()

	enrichSPDXHash(pkg, &packages.VersionWithDependencies{Integrity: &integrity}, &logger)

	assert.Len(t, pkg.PackageChecksums, 2)
	assert.Equal(t, existing, pkg.PackageChecksums[0])
}

func TestEnrichSPDXHash_NilIntegrityIsNoop(t *testing.T) {
	pkg := &v2_3.Package{}
	logger := zerolog.Nop()

	enrichSPDXHash(pkg, &packages.VersionWithDependencies{Integrity: nil}, &logger)

	assert.Nil(t, pkg.PackageChecksums)
}

func TestEnrichSBOM_SPDX_PopulatesChecksumFromIntegrity(t *testing.T) {
	ResetGlobalCache()
	packageVersionResponse := `{
		"integrity": "sha256-17ea4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631"
	}`
	packageResponse := `{}`
	setupHttpmock(t, &packageVersionResponse, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)
	bom := doc.BOM.(*v2_3.Document)
	bom.Packages = []*v2_3.Package{
		{
			PackageSPDXIdentifier: "pkg:pypi/fastapi@0.115.0",
			PackageName:           "fastapi",
			PackageVersion:        "0.115.0",
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{Category: common.CategoryPackageManager, RefType: "purl", Locator: "pkg:pypi/fastapi@0.115.0"},
			},
		},
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	assert.Equal(t, []common.Checksum{
		{
			Algorithm: common.SHA256,
			Value:     "17ea4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631",
		},
	}, bom.Packages[0].PackageChecksums)
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
