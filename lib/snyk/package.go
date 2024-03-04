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
	"context"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"

	"github.com/snyk/parlay/snyk/issues"
)

const (
	snykServer        = "https://api.snyk.io/rest"
	version           = "2023-04-28"
	snykAdvisorServer = "https://snyk.io/advisor"
	snykVulnDBServer  = "https://security.snyk.io/package"
)

func purlToSnykAdvisor(purl *packageurl.PackageURL) string {
	return map[string]string{
		packageurl.TypeNPM:    "npm-package",
		packageurl.TypePyPi:   "python",
		packageurl.TypeGolang: "golang",
		packageurl.TypeDocker: "docker",
	}[purl.Type]
}

func SnykAdvisorURL(purl *packageurl.PackageURL) string {
	ecosystem := purlToSnykAdvisor(purl)
	if ecosystem == "" {
		return ""
	}
	url := snykAdvisorServer + "/" + ecosystem + "/"
	if purl.Namespace != "" {
		url += purl.Namespace + "/"
	}
	url += purl.Name
	return url
}

func purlToSnykVulnDB(purl *packageurl.PackageURL) string {
	return map[string]string{
		packageurl.TypeCargo:     "cargo",
		packageurl.TypeCocoapods: "cocoapods",
		packageurl.TypeComposer:  "composer",
		packageurl.TypeGolang:    "golang",
		packageurl.TypeHex:       "hex",
		packageurl.TypeMaven:     "maven",
		packageurl.TypeNPM:       "npm",
		packageurl.TypeNuget:     "nuget",
		packageurl.TypePyPi:      "pip",
		packageurl.TypePub:       "pub",
		packageurl.TypeGem:       "rubygems",
		packageurl.TypeSwift:     "swift",
	}[purl.Type]
}

func SnykVulnURL(purl *packageurl.PackageURL) string {
	ecosystem := purlToSnykVulnDB(purl)
	if ecosystem == "" {
		return ""
	}
	url := snykVulnDBServer + "/" + ecosystem + "/"
	if purl.Namespace != "" {
		url += purl.Namespace + "%2F"
	}
	url += purl.Name
	return url
}

func GetPackageVulnerabilities(purl *packageurl.PackageURL, auth *securityprovider.SecurityProviderApiKey, orgID *uuid.UUID) (*issues.FetchIssuesPerPurlResponse, error) {
	client, err := issues.NewClientWithResponses(snykServer, issues.WithRequestEditorFn(auth.Intercept))
	if err != nil {
		return nil, err
	}

	params := issues.FetchIssuesPerPurlParams{Version: version}
	resp, err := client.FetchIssuesPerPurlWithResponse(context.Background(), *orgID, purl.ToString(), &params)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
