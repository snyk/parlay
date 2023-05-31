package deps

import (
	"fmt"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/zerolog"

	"github.com/snyk/parlay/lib/sbom"
)

func enrichOpenIssues(component cdx.Component, project Project) cdx.Component {
	return enrichProperty(component, "deps:open_issues_count", strconv.Itoa(project.OpenIssuesCount))
}

func enrichStars(component cdx.Component, project Project) cdx.Component {
	return enrichProperty(component, "deps:stars_count", strconv.Itoa(project.StarsCount))
}

func enrichScorecard(component cdx.Component, project Project) cdx.Component {
	return enrichProperty(component, "deps:scorecard", fmt.Sprintf("%.2f", project.Scorecard.OverallScore))
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

func enrichComponents(bom *cdx.BOM, enrichFuncs []func(cdx.Component, Project) cdx.Component) {
	wg := sizedwaitgroup.New(20)
	newComponents := make([]cdx.Component, len(*bom.Components))
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			if component.ExternalReferences != nil {
				for _, ref := range *component.ExternalReferences {
					if ref.Type == "vcs" {
						name := strings.ReplaceAll(ref.URL, "https://", "")
						proj, err := GetRepoData(name)
						if err == nil {
							for _, enrichFunc := range enrichFuncs {
								component = enrichFunc(component, *proj)
							}
						}
						break
					}
				}
			}
			newComponents[i] = component
			wg.Done()
		}(component, i)
	}
	wg.Wait()
	bom.Components = &newComponents
}

func EnrichSBOM(doc *sbom.SBOMDocument, logger *zerolog.Logger) {
	switch bom := doc.BOM.(type) {
	case *cdx.BOM:
		doc.BOM = EnrichCycloneDXSBOM(bom)
	default:
		logger.Debug().Msg("Unsupported SBOM format for deps.dev enrichment")
	}
}

func EnrichCycloneDXSBOM(bom *cdx.BOM) *cdx.BOM {
	if bom.Components == nil {
		return bom
	}

	enrichFuncs := []func(cdx.Component, Project) cdx.Component{
		enrichOpenIssues,
		enrichStars,
		enrichScorecard,
	}

	enrichComponents(bom, enrichFuncs)
	return bom
}
