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
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/parlay/lib/sbom"
)

func TestEnrichSBOM_SPDX(t *testing.T) {
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
			})
		})

	bom := &v2_3.Document{
		Packages: []*v2_3.Package{
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
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	EnrichSBOM(doc)

	pkgs := bom.Packages

	assert.Equal(t, "description", pkgs[0].PackageDescription)
	assert.Equal(t, "BSD-3-Clause", pkgs[0].PackageLicenseConcluded)
	assert.Equal(t, "https://github.com/spdx/tools-golang", pkgs[0].PackageHomePage)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, len(pkgs), calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
}
