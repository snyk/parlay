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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/lib/ecosystems"
)

func cdxEnrichExternalReference(component cdx.Component, url string, comment string, refType cdx.ExternalReferenceType) cdx.Component {
	ext := cdx.ExternalReference{
		URL:     url,
		Comment: comment,
		Type:    refType,
	}
	if component.ExternalReferences == nil {
		component.ExternalReferences = &[]cdx.ExternalReference{ext}
	} else {
		*component.ExternalReferences = append(*component.ExternalReferences, ext)
	}
	return component
}

func enrichCDX(bom *cdx.BOM) {
	comps := utils.DiscoverCDXComponents(bom)
	wg := sizedwaitgroup.New(20)
	for i := range comps {
		wg.Add()
		go func(component *cdx.Component) {
			defer wg.Done()
			purl, err := packageurl.FromString(component.PackageURL)
			if err != nil {
				return
			}
			resp, err := ecosystems.GetPackageData(purl)
			if err == nil && resp.JSON200 != nil && resp.JSON200.RepositoryUrl != nil {
				scorecardUrl := strings.ReplaceAll(*resp.JSON200.RepositoryUrl, "https://", "https://api.securityscorecards.dev/projects/")
				response, err := http.Get(scorecardUrl)
				if err == nil {
					defer response.Body.Close()
					if response.StatusCode == http.StatusOK {
						*component = cdxEnrichExternalReference(*component, scorecardUrl, "OpenSSF Scorecard", cdx.ERTypeOther)
					}
				}
			}
		}(comps[i])
	}
	wg.Wait()
}
