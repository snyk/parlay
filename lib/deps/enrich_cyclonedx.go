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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/zerolog"
)

func enrichOpenIssues(component cdx.Component, project Project) cdx.Component {
	if project.OpenIssuesCount != nil {
		return enrichProperty(component, "deps:open_issues_count", strconv.Itoa(*project.OpenIssuesCount))
	}
	return component
}

func enrichStars(component cdx.Component, project Project) cdx.Component {
	if project.StarsCount != nil {
		return enrichProperty(component, "deps:stars_count", strconv.Itoa(*project.StarsCount))
	}
	return component
}

func enrichScorecard(component cdx.Component, project Project) cdx.Component {
	if project.Scorecard == nil || project.Scorecard.OverallScore == nil {
		return component
	}
	return enrichProperty(component, "deps:scorecard", fmt.Sprintf("%.2f", *project.Scorecard.OverallScore))
}

func enrichForks(component cdx.Component, project Project) cdx.Component {
	if project.ForksCount != nil {
		return enrichProperty(component, "deps:forks_count", strconv.Itoa(*project.ForksCount))
	}
	return component
}

func enrichLicense(component cdx.Component, project Project) cdx.Component {
	if project.License != nil {
		return enrichProperty(component, "deps:license", *project.License)
	}
	return component
}

func enrichDescription(component cdx.Component, project Project) cdx.Component {
	if project.Description != nil {
		return enrichProperty(component, "deps:description", *project.Description)
	}
	return component
}

func enrichHomepage(component cdx.Component, project Project) cdx.Component {
	if project.Homepage != nil {
		return enrichProperty(component, "deps:homepage", *project.Homepage)
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

func enrichComponents(bom *cdx.BOM, enrichFuncs []func(cdx.Component, Project) cdx.Component, logger *zerolog.Logger, cache *projectCache) {
	wg := sizedwaitgroup.New(20)
	newComponents := make([]cdx.Component, len(*bom.Components))
	for i, component := range *bom.Components {
		wg.Add()
		go func(component cdx.Component, i int) {
			defer wg.Done()

			newComponents[i] = enrichComponentRecursive(component, enrichFuncs, logger, cache)
		}(component, i)
	}
	wg.Wait()
	bom.Components = &newComponents
}

func enrichComponentRecursive(component cdx.Component, enrichFuncs []func(cdx.Component, Project) cdx.Component, logger *zerolog.Logger, cache *projectCache) cdx.Component {
	var repoURL string
	var foundVCS bool

	// First try to find VCS reference in externalReferences
	if component.ExternalReferences != nil {
		for _, ref := range *component.ExternalReferences {
			if ref.Type == "vcs" {
				repoURL = ref.URL
				foundVCS = true
				break
			}
		}
	}

	// If no VCS reference found, try to get it from the package URL using deps.dev API
	if !foundVCS && component.PackageURL != "" {
		url, err := GetRepoURLFromPackage(component.PackageURL, logger)
		if err != nil {
			logger.Debug().
				Str("component", component.Name).
				Str("purl", component.PackageURL).
				Err(err).
				Msg("Failed to get repository URL from package")
		} else {
			repoURL = url
			foundVCS = true
		}
	}

	// If we have a repository URL, enrich the component
	if foundVCS && repoURL != "" {
		proj, err := GetRepoDataWithCache(repoURL, logger, cache)
		if err != nil {
			logger.Warn().
				Str("component", component.Name).
				Str("url", repoURL).
				Err(err).
				Msg("Failed to fetch deps.dev data for component")
		} else {
			for _, enrichFunc := range enrichFuncs {
				component = enrichFunc(component, *proj)
			}
		}
	}

	if component.Components != nil {
		children := *component.Components
		newChildren := make([]cdx.Component, len(children))
		for i, child := range children {
			newChildren[i] = enrichComponentRecursive(child, enrichFuncs, logger, cache)
		}
		component.Components = &newChildren
	}

	return component
}

func enrichCDX(bom *cdx.BOM, logger *zerolog.Logger) {
	if bom.Components == nil {
		return
	}

	enrichFuncs := []func(cdx.Component, Project) cdx.Component{
		enrichOpenIssues,
		enrichStars,
		enrichForks,
		enrichLicense,
		enrichDescription,
		enrichHomepage,
		enrichScorecard,
	}

	cache := newProjectCache()
	enrichComponents(bom, enrichFuncs, logger, cache)
}
