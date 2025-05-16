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

package osv

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/remeh/sizedwaitgroup"

	"github.com/snyk/parlay/internal/utils"
	"github.com/jvpascal/osvwrapper"
)

func cdxEnrichExternalReference(comp *cdx.Component, url, comment string, refType cdx.ExternalReferenceType) {
	ext := cdx.ExternalReference{
		URL:     url,
		Comment: comment,
		Type:    refType,
	}

	if comp.ExternalReferences == nil {
		comp.ExternalReferences = &[]cdx.ExternalReference{ext}
	} else {
		*comp.ExternalReferences = append(*comp.ExternalReferences, ext)
	}
}

func enrichCDX(bom *cdx.BOM) {
	comps := utils.DiscoverCDXComponents(bom)

	wg := sizedwaitgroup.New(20)

	for i := range comps {
		wg.Add()
		go func(component *cdx.Component) {
			defer wg.Done()

			vuln_report, err := osvwrapper.OSVQuery(component.PackageURL)
			if err != nil {
				return
			}

			cdxEnrichExternalReference(component, "https://api.osv.dev/v1/query", vuln_report, cdx.ERTypeVulnerabilityAssertion)
		}(comps[i])
	}

	wg.Wait()
}
