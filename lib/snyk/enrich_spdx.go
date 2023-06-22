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

package snyk

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"

	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/spdx/tools-golang/spdx"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/snyk/parlay/snyk/issues"
)

const (
	snykVulnerabilityDB_URI = "https://security.snyk.io"
)

func enrichSPDX(bom *spdx.Document) *spdx.Document {
	mutex := &sync.Mutex{}
	wg := sizedwaitgroup.New(20)
	vulnerabilities := make(map[*spdx_2_3.Package][]issues.CommonIssueModelVTwo)

	for i, pkg := range bom.Packages {
		wg.Add()
		go func(pkg *spdx_2_3.Package, i int) {
			purl, err := getPurlFromSPDXPackage(pkg)
			if err != nil {
				return
			}

			resp, err := GetPackageVulnerabilities(*purl)

			if err == nil {
				packageData := resp.Body
				var packageDoc issues.IssuesWithPurlsResponse
				if err := json.Unmarshal(packageData, &packageDoc); err == nil {
					if packageDoc.Data != nil {
						mutex.Lock()
						vulnerabilities[pkg] = *packageDoc.Data
						mutex.Unlock()
					}
				}
			}
			wg.Done()
		}(pkg, i)
	}
	wg.Wait()

	for pkg, vulns := range vulnerabilities {
		for _, issue := range vulns {
			if issue.Id == nil {
				continue
			}

			ref := &spdx_2_3.PackageExternalReference{
				Category: spdx.CategorySecurity,
				RefType:  spdx.SecurityAdvisory,
				Locator: fmt.Sprintf(
					"%s/vuln/%s",
					snykVulnerabilityDB_URI,
					url.PathEscape(*issue.Id),
				),
			}
			if issue.Attributes.Title != nil {
				ref.ExternalRefComment = *issue.Attributes.Title
			}

			pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, ref)
		}
	}

	return bom
}

func getPurlFromSPDXPackage(pkg *spdx_2_3.Package) (*packageurl.PackageURL, error) {
	var p string

	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType == "purl" {
			p = ref.Locator
			break
		}
	}

	if p == "" {
		return nil, fmt.Errorf("no purl on package %s", pkg.PackageName)
	}

	purl, err := packageurl.FromString(p)
	if err != nil {
		return nil, err
	}

	return &purl, nil
}
