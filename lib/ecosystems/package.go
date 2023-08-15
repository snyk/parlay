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

package ecosystems

import (
	"context"
	"fmt"
	"net/url"

	"github.com/package-url/packageurl-go"

	"github.com/snyk/parlay/ecosystems/packages"
)

const server = "https://packages.ecosyste.ms/api/v1"

func GetPackageData(purl packageurl.PackageURL) (*packages.GetRegistryPackageResponse, error) {
	client, err := packages.NewClientWithResponses(server)
	if err != nil {
		return nil, err
	}

	// Ecosyste.ms has a purl based API, but unfortunately slower
	// so we break the purl down to registry and name values locally
	// params := packages.LookupPackageParams{Purl: &p}
	// resp, err := client.LookupPackageWithResponse(context.Background(), &params)
	name := purlToEcosystemsName(purl)
	registry := purlToEcosystemsRegistry(purl)
	resp, err := client.GetRegistryPackageWithResponse(context.Background(), registry, name)

	if err != nil {
		return nil, err
	}
	return resp, nil
}

func purlToEcosystemsRegistry(purl packageurl.PackageURL) string {
	return map[string]string{
		packageurl.TypeApk:       "alpine-edge",
		packageurl.TypeCargo:     "crates.io",
		packageurl.TypeCocoapods: "cocoapod.org",
		packageurl.TypeComposer:  "packagist.org",
		packageurl.TypeDocker:    "hub.docker.com",
		packageurl.TypeGem:       "rubygems.org",
		packageurl.TypeGolang:    "proxy.golang.org",
		packageurl.TypeHex:       "hex.pm",
		packageurl.TypeMaven:     "repo1.maven.org",
		packageurl.TypeNPM:       "npmjs.org",
		packageurl.TypeNuget:     "nuget.org",
		packageurl.TypePyPi:      "pypi.org",
		packageurl.TypeSwift:     "swiftpackageindex.com",
	}[purl.Type]
}

func purlToEcosystemsName(purl packageurl.PackageURL) string {
	if purl.Namespace == "" {
		return purl.Name
	}

	var name string
	// npm names in the ecosyste.ms API include the purl namespace
	// followed by a / and are url encoded. Other package managers
	// appear to separate the purl namespace and name with a :
	switch purl.Type {
	case "npm":
		name = url.QueryEscape(fmt.Sprintf("%s/%s", purl.Namespace, purl.Name))
	case "golang":
		name = fmt.Sprintf("%s/%s", purl.Namespace, purl.Name)
	default:
		name = fmt.Sprintf("%s:%s", purl.Namespace, purl.Name)
	}
	return name
}
