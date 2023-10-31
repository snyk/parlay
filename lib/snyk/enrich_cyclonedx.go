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
	"strconv"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/zerolog"

	"github.com/snyk/parlay/snyk/issues"
)

func enrichCycloneDX(bom *cdx.BOM, logger zerolog.Logger) *cdx.BOM {
	if bom.Components == nil {
		return bom
	}

	wg := sizedwaitgroup.New(20)
	var mutex = &sync.Mutex{}
	vulnerabilities := make(map[cdx.Component][]issues.CommonIssueModelVTwo)

	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			defer wg.Done()

			purl, err := packageurl.FromString(component.PackageURL)
			if err != nil {
				logger.Debug().
					Err(err).
					Str("BOM-Ref", string(component.BOMRef)).
					Msg("Could not identify package.")
				return
			}

			resp, err := GetPackageVulnerabilities(purl)
			if err != nil {
				logger.Err(err).
					Str("purl", purl.ToString()).
					Msg("Failed to fetch vulnerabilities for package.")
				return
			}

			packageData := resp.Body
			var packageDoc issues.IssuesWithPurlsResponse
			if err := json.Unmarshal(packageData, &packageDoc); err != nil {
				logger.Err(err).
					Str("status", resp.Status()).
					Msg("Failed to decode Snyk vulnerability response.")
				return
			}

			if packageDoc.Data != nil {
				mutex.Lock()
				vulnerabilities[component] = *packageDoc.Data
				mutex.Unlock()
			}
		}(component, i)
	}

	wg.Wait()

	var vulns []cdx.Vulnerability
	for k, v := range vulnerabilities {
		for _, issue := range v {
			vuln := cdx.Vulnerability{
				BOMRef: k.BOMRef,
			}
			if issue.Id != nil {
				vuln.ID = *issue.Id
			}
			if issue.Attributes.Title != nil {
				vuln.Description = *issue.Attributes.Title
			}
			if issue.Attributes.Description != nil {
				vuln.Detail = *issue.Attributes.Description
			}
			if issue.Attributes.CreatedAt != nil {
				created := *issue.Attributes.CreatedAt
				vuln.Created = created.UTC().Format(time.RFC3339)
			}
			if issue.Attributes.UpdatedAt != nil {
				updated := *issue.Attributes.UpdatedAt
				vuln.Updated = updated.UTC().Format(time.RFC3339)
			}
			if issue.Attributes.Problems != nil {
				problems := *issue.Attributes.Problems
				for _, problem := range problems {
					switch problem.Source {
					case "CWE":
						id := problem.Id[4:]
						cwe, err := strconv.Atoi(id)
						if err == nil {
							if vuln.CWEs == nil {
								cwes := []int{cwe}
								vuln.CWEs = &cwes
							} else {
								*vuln.CWEs = append(*vuln.CWEs, cwe)
							}
						}
					case "CVE", "GHAS", "RHSA":
						s := cdx.Source{
							Name: problem.Source,
						}
						ref := cdx.VulnerabilityReference{
							ID:     problem.Id,
							Source: &s,
						}
						if vuln.References == nil {
							refs := []cdx.VulnerabilityReference{ref}
							vuln.References = &refs
						} else {
							*vuln.References = append(*vuln.References, ref)
						}
					}
				}
				if issue.Attributes.Slots.References != nil {
					for _, ref := range *issue.Attributes.Slots.References {
						ad := cdx.Advisory{
							Title: *ref.Title,
							URL:   *ref.Url,
						}
						if vuln.Advisories == nil {
							ads := []cdx.Advisory{ad}
							vuln.Advisories = &ads
						} else {
							*vuln.Advisories = append(*vuln.Advisories, ad)
						}
					}
				}

				if issue.Attributes.Severities != nil {
					for _, sev := range *issue.Attributes.Severities {
						source := cdx.Source{
							Name: "Snyk",
							URL:  "https://security.snyk.io",
						}
						if sev.Score != nil {
							score := float64(*sev.Score)
							rating := cdx.VulnerabilityRating{
								Source:   &source,
								Score:    &score,
								Severity: levelToCdxSeverity(sev.Level),
								Method:   "CVSSv31",
								Vector:   *sev.Vector,
							}
							if vuln.Ratings == nil {
								ratings := []cdx.VulnerabilityRating{rating}
								vuln.Ratings = &ratings
							} else {
								*vuln.Ratings = append(*vuln.Ratings, rating)
							}
						}
					}
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	if len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	return bom
}

func levelToCdxSeverity(level *string) (severity cdx.Severity) {
	switch *level {
	case "critical":
		severity = cdx.SeverityCritical
	case "high":
		severity = cdx.SeverityHigh
	case "medium":
		severity = cdx.SeverityMedium
	case "low":
		severity = cdx.SeverityLow
	default:
		severity = cdx.SeverityUnknown
	}
	return
}
