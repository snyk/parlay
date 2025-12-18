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

package deps

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/zerolog"
	spdx "github.com/spdx/tools-golang/spdx"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func enrichSPDX(bom *spdx.Document, logger *zerolog.Logger) {
	wg := sizedwaitgroup.New(20)
	cache := newProjectCache()

	for i, pkg := range bom.Packages {
		wg.Add()

		go func(pkg *spdx_2_3.Package, i int) {
			defer wg.Done()

			// Look for VCS external references
			var repoURL string
			for _, ref := range pkg.PackageExternalReferences {
				if ref.RefType == "vcs" || (ref.RefType == "url" && (strings.Contains(ref.Locator, "github.com") || strings.Contains(ref.Locator, "gitlab.com") || strings.Contains(ref.Locator, "bitbucket.org"))) {
					repoURL = ref.Locator
					break
				}
			}

			// If no VCS reference found, skip this package
			if repoURL == "" {
				logger.Debug().
					Str("package", pkg.PackageName).
					Msg("No VCS reference found, skipping deps.dev enrichment")
				return
			}

			proj, err := GetRepoDataWithCache(repoURL, logger, cache)
			if err != nil {
				logger.Debug().
					Str("package", pkg.PackageName).
					Str("url", repoURL).
					Err(err).
					Msg("Failed to get repository data from deps.dev")
				return
			}

			// Add external references for each piece of data
			if proj.OpenIssuesCount != nil {
				enrichSPDXExternalRef(pkg, "deps:open_issues_count", strconv.Itoa(*proj.OpenIssuesCount))
			}
			if proj.StarsCount != nil {
				enrichSPDXExternalRef(pkg, "deps:stars_count", strconv.Itoa(*proj.StarsCount))
			}
			if proj.ForksCount != nil {
				enrichSPDXExternalRef(pkg, "deps:forks_count", strconv.Itoa(*proj.ForksCount))
			}

			if proj.License != nil && *proj.License != "" {
				enrichSPDXExternalRef(pkg, "deps:license", *proj.License)
			}
			if proj.Description != nil && *proj.Description != "" {
				enrichSPDXExternalRef(pkg, "deps:description", *proj.Description)
			}
			if proj.Homepage != nil && *proj.Homepage != "" {
				enrichSPDXExternalRef(pkg, "deps:homepage", *proj.Homepage)
			}

			if proj.Scorecard != nil && proj.Scorecard.OverallScore != nil {
				enrichSPDXExternalRef(pkg, "deps:scorecard", fmt.Sprintf("%.2f", *proj.Scorecard.OverallScore))
			}

			logger.Debug().
				Str("package", pkg.PackageName).
				Msg("Successfully enriched package with deps.dev data")
		}(pkg, i)
	}

	wg.Wait()
}

func enrichSPDXExternalRef(pkg *spdx_2_3.Package, name string, value string) {
	ref := &spdx_2_3.PackageExternalReference{
		Category:           spdx.CategoryOther,
		RefType:            name,
		Locator:            value,
		ExternalRefComment: fmt.Sprintf("deps.dev %s", name),
	}

	pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, ref)
}
