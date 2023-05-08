package lib

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/snyk/issues"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/remeh/sizedwaitgroup"
)

func enrichDescription(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.Description != nil {
		component.Description = *packageData.Description
	}
	return component
}

func enrichLicense(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.NormalizedLicenses != nil {
		if len(packageData.NormalizedLicenses) > 0 {
			expression := packageData.NormalizedLicenses[0]
			licences := cdx.LicenseChoice{Expression: expression}
			component.Licenses = &cdx.Licenses{licences}
		}
	}
	return component
}

func enrichExternalReference(component cdx.Component, packageData packages.Package, url *string, refType cdx.ExternalReferenceType) cdx.Component {
	if url == nil {
		return component
	}
	ext := cdx.ExternalReference{
		URL:  *url,
		Type: refType,
	}
	if component.ExternalReferences == nil {
		component.ExternalReferences = &[]cdx.ExternalReference{ext}
	} else {
		*component.ExternalReferences = append(*component.ExternalReferences, ext)
	}
	return component
}

func enrichProperty(component cdx.Component, name string, value string) cdx.Component {
	prop := cdx.Property{
		Name:  name,
		Value: value,
	}
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{prop}
	} else {
		*component.Properties = append(*component.Properties, prop)
	}
	return component
}

func enrichHomepage(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.Homepage, cdx.ERTypeWebsite)
}

func enrichRegistryURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RegistryUrl, cdx.ERTypeDistribution)
}

func enrichRepositoryURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.RepositoryUrl, cdx.ERTypeVCS)
}

func enrichDocumentationURL(component cdx.Component, packageData packages.Package) cdx.Component {
	return enrichExternalReference(component, packageData, packageData.DocumentationUrl, cdx.ERTypeDocumentation)
}

func enrichFirstReleasePublishedAt(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.FirstReleasePublishedAt == nil {
		return component
	}
	timestamp := packageData.FirstReleasePublishedAt.UTC().Format(time.RFC3339)
	return enrichProperty(component, "ecosystems:first_release_published_at", timestamp)
}

func enrichLatestReleasePublishedAt(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.LatestReleasePublishedAt == nil {
		return component
	}
	timestamp := packageData.LatestReleasePublishedAt.UTC().Format(time.RFC3339)
	return enrichProperty(component, "ecosystems:latest_release_published_at", timestamp)
}

func enrichRepoArchived(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		if archived, ok := (*packageData.RepoMetadata)["archived"].(bool); ok && archived {
			return enrichProperty(component, "ecosystems:repository_archived", "true")
		}
	}
	return component
}

func enrichLocation(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if location, ok := ownerRecord["location"].(string); ok {
				return enrichProperty(component, "ecosystems:owner_location", location)
			}
		}
	}
	return component
}

func enrichAuthor(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if name, ok := ownerRecord["name"].(string); ok {
				component.Author = name
				return component
			}
		}
	}
	return component
}

func enrichSupplier(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata
		if ownerRecord, ok := meta["owner_record"].(map[string]interface{}); ok {
			if name, ok := ownerRecord["name"].(string); ok {
				supplier := cdx.OrganizationalEntity{
					Name: name,
				}
				if website, ok := ownerRecord["website"].(string); ok {
					websites := []string{website}
					supplier.URL = &websites
				}
				component.Supplier = &supplier
				return component
			}
		}
	}
	return component
}

func enrichTopics(component cdx.Component, packageData packages.Package) cdx.Component {
	if packageData.RepoMetadata != nil {
		meta := *packageData.RepoMetadata

		if topics, ok := meta["topics"].([]interface{}); ok {
			for _, topic := range topics {
				component = enrichProperty(component, "ecosystems:topic", topic.(string))
			}
		}
		return component
	}
	return component
}

func enrichComponentsWithEcosystems(bom *cdx.BOM, enrichFuncs []func(cdx.Component, packages.Package) cdx.Component) {
	wg := sizedwaitgroup.New(20)
	newComponents := make([]cdx.Component, len(*bom.Components))
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			purl, _ := packageurl.FromString(component.PackageURL)
			resp, err := GetPackageData(purl)
			if err == nil {
				packageData := resp.JSON200
				for _, enrichFunc := range enrichFuncs {
					component = enrichFunc(component, *packageData)
				}
			}
			newComponents[i] = component
			wg.Done()
		}(component, i)
	}
	wg.Wait()
	bom.Components = &newComponents
}

func EnrichSBOMWithEcosystems(bom *cdx.BOM) *cdx.BOM {
	if bom.Components == nil {
		return bom
	}

	enrichFuncs := []func(cdx.Component, packages.Package) cdx.Component{
		enrichDescription,
		enrichLicense,
		enrichHomepage,
		enrichRegistryURL,
		enrichRepositoryURL,
		enrichDocumentationURL,
		enrichFirstReleasePublishedAt,
		enrichLatestReleasePublishedAt,
		enrichRepoArchived,
		enrichLocation,
		enrichTopics,
		enrichAuthor,
		enrichSupplier,
	}

	enrichComponentsWithEcosystems(bom, enrichFuncs)
	return bom
}

func EnrichSBOMWithSnyk(bom *cdx.BOM) *cdx.BOM {
	if bom.Components == nil {
		return bom
	}

	wg := sizedwaitgroup.New(20)
	var mutex = &sync.Mutex{}
	vulnerabilities := make(map[cdx.Component][]issues.CommonIssueModelVTwo)
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			purl, _ := packageurl.FromString(component.PackageURL)
			resp, err := GetPackageVulnerabilities(purl)

			if err == nil {
				packageData := resp.Body
				var packageDoc issues.IssuesWithPurlsResponse
				if err := json.Unmarshal(packageData, &packageDoc); err == nil {
					if packageDoc.Data != nil {
						mutex.Lock()
						vulnerabilities[component] = *packageDoc.Data
						mutex.Unlock()
					}
				}
			}
			wg.Done()
		}(component, i)
	}
	wg.Wait()
	var vulns []cdx.Vulnerability
	for k, v := range vulnerabilities {
		if v != nil {
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
				vulns = append(vulns, vuln)
			}
		}
	}
	bom.Vulnerabilities = &vulns
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
