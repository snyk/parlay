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
	"github.com/rs/zerolog"
	"github.com/spdx/tools-golang/spdx"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/snyk/issues"
)

type spdxEnricher = func(*Config, *spdx_2_3.Package, *packageurl.PackageURL)

var spdxEnrichers = []spdxEnricher{
	enrichSPDXSnykAdvisorData,
	enrichSPDXSnykVulnerabilityDBData,
}

func enrichSPDXSnykAdvisorData(cfg *Config, component *spdx_2_3.Package, purl *packageurl.PackageURL) {
	url := SnykAdvisorURL(cfg, purl)
	if url != "" {
		ext := &spdx_2_3.PackageExternalReference{
			Locator:            url,
			RefType:            "advisory",
			Category:           spdx.CategoryOther,
			ExternalRefComment: "Snyk Advisor",
		}
		if component.PackageExternalReferences == nil {
			component.PackageExternalReferences = []*spdx_2_3.PackageExternalReference{ext}
		} else {
			component.PackageExternalReferences = append(component.PackageExternalReferences, ext)
		}
	}
}

func enrichSPDXSnykVulnerabilityDBData(cfg *Config, component *spdx_2_3.Package, purl *packageurl.PackageURL) {
	url := SnykVulnURL(cfg, purl)
	if url != "" {
		ext := &spdx_2_3.PackageExternalReference{
			Locator:            url,
			RefType:            "url",
			Category:           spdx.CategoryOther,
			ExternalRefComment: "Snyk Vulnerability DB",
		}
		if component.PackageExternalReferences == nil {
			component.PackageExternalReferences = []*spdx_2_3.PackageExternalReference{ext}
		} else {
			component.PackageExternalReferences = append(component.PackageExternalReferences, ext)
		}
	}
}

func enrichSPDX(cfg *Config, bom *spdx.Document, logger *zerolog.Logger) *spdx.Document {
	auth, err := AuthFromToken(cfg.APIToken)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("Failed to authenticate")
		return nil
	}

	orgID, err := SnykOrgID(cfg, auth)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("Failed to infer preferred Snyk organization")
		return nil
	}

	mutex := &sync.Mutex{}
	wg := sizedwaitgroup.New(20)
	vulnerabilities := make(map[*spdx_2_3.Package][]issues.CommonIssueModelVTwo)

	packages := bom.Packages
	logger.Debug().Msgf("Detected %d packages", len(packages))

	for i, pkg := range packages {
		wg.Add()

		go func(pkg *spdx_2_3.Package, i int) {
			defer wg.Done()
			l := logger.With().Str("SPDXID", string(pkg.PackageSPDXIdentifier)).Logger()

			purl, err := utils.GetPurlFromSPDXPackage(pkg)
			if err != nil || purl == nil {
				l.Debug().Msg("Could not identify package")
				return
			}
			for _, enrichFn := range spdxEnrichers {
				enrichFn(cfg, pkg, purl)
			}
			resp, err := GetPackageVulnerabilities(cfg, purl, auth, orgID)
			if err != nil {
				l.Err(err).
					Str("purl", purl.ToString()).
					Msg("Failed to fetch vulnerabilities for package")
				return
			}

			packageData := resp.Body
			var packageDoc issues.IssuesWithPurlsResponse
			if err := json.Unmarshal(packageData, &packageDoc); err != nil {
				l.Err(err).
					Str("status", resp.Status()).
					Msg("Failed to decode Snyk vulnerability response")
				return
			}

			if packageDoc.Data != nil {
				mutex.Lock()
				vulnerabilities[pkg] = *packageDoc.Data
				mutex.Unlock()
			}
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
					snykVulnerabilityDBWebURL,
					url.PathEscape(*issue.Id)),
			}

			if issue.Attributes.Title != nil {
				ref.ExternalRefComment = *issue.Attributes.Title
			}

			pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, ref)
		}
	}

	return bom
}
