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
	"net/http"
	"strings"

	"github.com/remeh/sizedwaitgroup"
	"github.com/spdx/tools-golang/spdx"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/ecosystems"
)

func enrichSPDX(bom *spdx.Document) {
	wg := sizedwaitgroup.New(20)

	for i, pkg := range bom.Packages {
		wg.Add()

		go func(pkg *spdx_2_3.Package, i int) {
			defer wg.Done()

			purl, err := utils.GetPurlFromSPDXPackage(pkg)
			if err != nil {
				return
			}

			resp, err := ecosystems.GetPackageData(*purl)
			if err != nil || resp.JSON200 == nil || resp.JSON200.RepositoryUrl == nil {
				return
			}

			scURL := strings.ReplaceAll(*resp.JSON200.RepositoryUrl, "https://", "https://api.securityscorecards.dev/projects/")

			response, err := http.Get(scURL)
			if err != nil || response.StatusCode != http.StatusOK {
				return
			}

			pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, &spdx_2_3.PackageExternalReference{
				Category: spdx.CategoryOther,
				RefType:  "openssfscorecard",
				Locator:  scURL,
			})
		}(pkg, i)
	}

	wg.Wait()
}
