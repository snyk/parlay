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

	"github.com/snyk/parlay/internal/utils"
	"github.com/snyk/parlay/snyk/issues"
)

type cdxEnricher = func(*Config, *cdx.Component, *packageurl.PackageURL)

type cdxPurlGroup struct {
	purl       packageurl.PackageURL
	components []*cdx.Component
	bomRef     string
}

var cdxEnrichers = []cdxEnricher{
	enrichCDXSnykAdvisorData,
	enrichCDXSnykVulnerabilityDBData,
}

func enrichCDXSnykVulnerabilityDBData(cfg *Config, component *cdx.Component, purl *packageurl.PackageURL) {
	url := SnykVulnURL(cfg, purl)
	if url != "" {
		ext := cdx.ExternalReference{
			URL:     url,
			Comment: "Snyk Vulnerability DB",
			Type:    "Other",
		}
		if component.ExternalReferences == nil {
			component.ExternalReferences = &[]cdx.ExternalReference{ext}
		} else {
			*component.ExternalReferences = append(*component.ExternalReferences, ext)
		}
	}
}

func enrichCDXSnykAdvisorData(cfg *Config, component *cdx.Component, purl *packageurl.PackageURL) {
	url := SnykAdvisorURL(cfg, purl)
	if url != "" {
		ext := cdx.ExternalReference{
			URL:     url,
			Comment: "Snyk Advisor",
			Type:    "Other",
		}
		if component.ExternalReferences == nil {
			component.ExternalReferences = &[]cdx.ExternalReference{ext}
		} else {
			*component.ExternalReferences = append(*component.ExternalReferences, ext)
		}
	}
}

func enrichCycloneDX(cfg *Config, bom *cdx.BOM, logger *zerolog.Logger) *cdx.BOM {
	auth, err := AuthFromToken(cfg.APIToken)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to authenticate")
		return nil
	}

	orgID, err := SnykOrgID(cfg, auth)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to infer preferred Snyk organization")
		return nil
	}
	logger.Debug().Str("org_id", orgID.String()).Msg("Inferred Snyk organization ID")

	var mutex = &sync.Mutex{}
	vulnerabilities := make(map[cdx.Component][]issues.CommonIssueModelVThree)
	wg := sizedwaitgroup.New(20)

	comps := utils.DiscoverCDXComponents(bom)
	logger.Debug().Msgf("Detected %d packages", len(comps))

	// Group components by PURL to deduplicate API calls
	purlGroups := make(map[string]*cdxPurlGroup)
	for i := range comps {
		component := comps[i]
		l := logger.With().Str("bom-ref", component.BOMRef).Logger()

		purl, err := packageurl.FromString(component.PackageURL)
		if err != nil {
			l.Debug().
				Err(err).
				Msg("Could not identify package")
			continue
		}
		for _, enrichFunc := range cdxEnrichers {
			enrichFunc(cfg, component, &purl)
		}

		key := purl.ToString()
		group, ok := purlGroups[key]
		if !ok {
			group = &cdxPurlGroup{purl: purl, bomRef: component.BOMRef}
			purlGroups[key] = group
		}
		group.components = append(group.components, component)
	}

	// Fetch vulnerabilities for each unique PURL
	for _, group := range purlGroups {
		group := group
		wg.Add()
		go func() {
			defer wg.Done()
			l := logger.With().
				Str("bom-ref", group.bomRef).
				Str("purl", group.purl.ToString()).
				Logger()

			resp, err := GetPackageVulnerabilities(cfg, &group.purl, auth, orgID, logger)
			if err != nil {
				l.Err(err).
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
				for _, component := range group.components {
					vulnerabilities[*component] = *packageDoc.Data
				}
				mutex.Unlock()
			}
		}()
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
						var source cdx.Source
						if sev.Source != nil {
							source = cdx.Source{
								Name: *sev.Source,
							}
						} else {
							source = cdx.Source{
								Name: "Snyk",
							}
						}

						if source.Name == "Snyk" {
							source.URL = snykVulnerabilityDBWebURL
						}

						if sev.Score != nil {
							score := float64(*sev.Score)
							rating := cdx.VulnerabilityRating{
								Source:   &source,
								Score:    &score,
								Severity: levelToCdxSeverity(sev.Level),
								Method:   versionToCdxMethod(sev.Version),
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

	logger.Debug().Msgf("Found %d vulnerabilities", len(vulns))

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

func versionToCdxMethod(version *string) (method cdx.ScoringMethod) {
	switch *version {
	case "3.0":
		method = cdx.ScoringMethodCVSSv3
	case "3.1":
		method = cdx.ScoringMethodCVSSv31
	case "4.0":
		method = cdx.ScoringMethodCVSSv4
	default:
		method = cdx.ScoringMethodOther
	}
	return
}
