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

func TestEnrichSBOM_SPDX(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~^https://packages.ecosyste.ms/api/v1/registries/.*/packages/.*/versions`,
		func(r *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				// This is the license we expect to see for the specific package version
				"licenses": "MIT,Unknown",
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
				"homepage": "https://github.com/spdx/tools-golang",
				"repo_metadata": map[string]interface{}{
					"owner_record": map[string]interface{}{
						"name": "Acme Corp",
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

	pkgs := bom.Packages

	lics := bom.OtherLicenses
	assert.Len(t, lics, 1)

	assert.Equal(t, "description", pkgs[0].PackageDescription)
	assert.Equal(t, fmt.Sprintf("(MIT OR %s)", lics[0].LicenseIdentifier), pkgs[0].PackageLicenseConcluded)
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
