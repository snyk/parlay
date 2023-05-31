package deps

import (
  "fmt"
	"strings"

	"github.com/edoardottt/depsdev/pkg/depsdev"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/remeh/sizedwaitgroup"
)

func enrichOpenIssues(component cdx.Component, project depsdev.Project) cdx.Component {
  return enrichProperty(component, "deps:open_issues_count", project.OpenIssuesCount)
}

func enrichStars(component cdx.Component, project depsdev.Project) cdx.Component {
  return enrichProperty(component, "deps:stars_count", project.StarsCount)
}

func enrichScorecard(component cdx.Component, project depsdev.Project) cdx.Component {
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

func enrichComponents(bom *cdx.BOM, enrichFuncs []func(cdx.Component, depsdev.Project) cdx.Component) {
	wg := sizedwaitgroup.New(20)
	newComponents := make([]cdx.Component, len(*bom.Components))
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			if component.ExternalReferences != nil {
				for _, ref := range *component.ExternalReferences {
					if ref.Type == "vcs" {
						name := strings.ReplaceAll(ref.URL, "https://", "")
						proj, err := depsdev.GetProject(name)
						if err == nil {
							for _, enrichFunc := range enrichFuncs {
								component = enrichFunc(component, proj)
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

func EnrichSBOM(bom *cdx.BOM) *cdx.BOM {
	if bom.Components == nil {
		return bom
	}

	enrichFuncs := []func(cdx.Component, depsdev.Project) cdx.Component{
		enrichOpenIssues,
		enrichStars,
		enrichScorecard,
	}

	enrichComponents(bom, enrichFuncs)
	return bom
}
