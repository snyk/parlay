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
	assert.Equal(t, "(BSD-3-Clause OR Apache-2.0)", pkgs[0].PackageLicenseConcluded)
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

func TestEnrichSBOM_SPDX_InvalidLicense(t *testing.T) {
	ResetGlobalCache()

	packageVersionResponse := `{
		"licenses": "MIT,The Apache Software License, Version 2.0"
	}`
	packageResponse := `{}`
	setupHttpmock(t, &packageVersionResponse, &packageResponse)
	defer httpmock.DeactivateAndReset()

	doc, err := sbom.DecodeSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`))
	require.NoError(t, err)

	bom, ok := doc.BOM.(*v2_3.Document)
	require.True(t, ok)

	bom.Packages = []*v2_3.Package{
		spdxPackageWithPurl("pkg:golang/github.com/spdx/tools-golang@v0.5.2"),
		spdxPackageWithPurl("pkg:golang/github.com/spdx/tools-golang@v0.5.3"),
	}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	// The valid identifier survives; only the unparseable part becomes a ref.
	assert.Equal(t,
		"(MIT OR LicenseRef-The-Apache-Software-License OR LicenseRef-Version-2.0)",
		bom.Packages[0].PackageLicenseConcluded,
	)

	// Both packages carry the same licenses, so the refs are declared once.
	assert.Equal(t, []*v2_3.OtherLicense{
		{
			LicenseIdentifier: "LicenseRef-The-Apache-Software-License",
			ExtractedText:     "The Apache Software License",
			LicenseName:       "The Apache Software License",
		},
		{
			LicenseIdentifier: "LicenseRef-Version-2.0",
			ExtractedText:     "Version 2.0",
			LicenseName:       "Version 2.0",
		},
	}, bom.OtherLicenses)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, doc.Encode(buf))
}

func spdxPackageWithPurl(purl string) *v2_3.Package {
	return &v2_3.Package{
		PackageSPDXIdentifier: common.ElementID(purl),
		PackageExternalReferences: []*v2_3.PackageExternalReference{
			{
				Category: common.CategoryPackageManager,
				RefType:  "purl",
				Locator:  purl,
			},
		},
	}
}

func TestEnrichSPDXLicense_CollidingRefs(t *testing.T) {
	// Two different license strings that sanitize to the same LicenseRef must
	// still resolve to their own extracted text.
	first := "Apache 2.0/MIT"
	second := "Apache-2.0-MIT"

	bom := &v2_3.Document{}
	licenseRefs := map[string]string{}
	pkgA, pkgB := &v2_3.Package{}, &v2_3.Package{}

	enrichSPDXLicense(bom, pkgA, licenseRefs, &packages.VersionWithDependencies{Licenses: &first}, nil)
	enrichSPDXLicense(bom, pkgB, licenseRefs, &packages.VersionWithDependencies{Licenses: &second}, nil)

	require.Len(t, bom.OtherLicenses, 2)
	assert.NotEqual(t, pkgA.PackageLicenseConcluded, pkgB.PackageLicenseConcluded)

	texts := map[string]string{}
	for _, other := range bom.OtherLicenses {
		texts[string(other.LicenseIdentifier)] = other.ExtractedText
	}
	assert.Equal(t, first, texts[pkgA.PackageLicenseConcluded])
	assert.Equal(t, second, texts[pkgB.PackageLicenseConcluded])
}
