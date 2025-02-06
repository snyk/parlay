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

func testEnrichSBOM(t *testing.T, ecosysteMsPackageResponse map[string]interface{}, ecosysteMsRegistryResponse map[string]interface{}, assertions func(bom *v2_3.Document)) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries/.*/packages/.*/versions`,
		func(r *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, ecosysteMsPackageResponse)
		},
	)
	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, ecosysteMsRegistryResponse)
		},
	)

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

	assertions(bom)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, len(pkgs), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])

	buf := bytes.NewBuffer(nil)
	require.NoError(t, doc.Encode(buf))
}

func TestEnrichSBOM_SPDX(t *testing.T) {
	testEnrichSBOM(
		t,
		map[string]interface{}{
			"licenses": "MIT",
		},
		map[string]interface{}{
			"description":         "description",
			"normalized_licenses": []string{"BSD-3-Clause"},
			"homepage":            "https://github.com/spdx/tools-golang",
			"repo_metadata": map[string]interface{}{
				"owner_record": map[string]interface{}{
					"name": "Acme Corp",
				},
			},
		},
		func(bom *v2_3.Document) {
			pkgs := bom.Packages
			assert.Equal(t, "description", pkgs[0].PackageDescription)
			assert.Equal(t, "MIT", pkgs[0].PackageLicenseConcluded)
			assert.Equal(t, "https://github.com/spdx/tools-golang", pkgs[0].PackageHomePage)
			assert.Equal(t, "Organization", pkgs[0].PackageSupplier.SupplierType)
			assert.Equal(t, "Acme Corp", pkgs[0].PackageSupplier.Supplier)
		},
	)
}

func TestEnrichSBOM_MissingVersionedLicense(t *testing.T) {
	testEnrichSBOM(
		t,
		map[string]interface{}{
			"licenses": "",
		},
		map[string]interface{}{
			"description":         "description",
			"normalized_licenses": []string{"BSD-3-Clause", "Apache-2.0"},
			"homepage":            "https://github.com/spdx/tools-golang",
			"repo_metadata": map[string]interface{}{
				"owner_record": map[string]interface{}{
					"name": "Acme Corp",
				},
			},
		},
		func(bom *v2_3.Document) {
			pkgs := bom.Packages
			assert.Equal(t, "description", pkgs[0].PackageDescription)
			assert.Equal(t, "BSD-3-Clause,Apache-2.0", pkgs[0].PackageLicenseConcluded)
			assert.Equal(t, "https://github.com/spdx/tools-golang", pkgs[0].PackageHomePage)
			assert.Equal(t, "Organization", pkgs[0].PackageSupplier.SupplierType)
			assert.Equal(t, "Acme Corp", pkgs[0].PackageSupplier.Supplier)
		},
	)
}

func TestEnrichSBOM_SPDX_NoSupplierName(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"description": "description",
				"normalized_licenses": []string{
					"BSD-3-Clause",
				},
				"homepage": "https://github.com/spdx/tools-golang",
				"repo_metadata": map[string]interface{}{
					"owner_record": map[string]interface{}{
						"name": "",
					},
				},
			})
		})

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
