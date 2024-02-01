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
	name := purl.Name

	if purl.Namespace == "" {
		return name
	}

	switch purl.Type {
	// Most ecosystems require the package to be identified by the namespace
	// and name separated by a forward slash "/".
	default:
		name = fmt.Sprintf("%s/%s", purl.Namespace, purl.Name)

	// ecosyste.ms maven requires the group ID and artifact ID to be separated
	// by a colon ":",
	case packageurl.TypeMaven:
		name = fmt.Sprintf("%s:%s", purl.Namespace, purl.Name)

	// ecosyste.ms npm requires the combination of namespace and name to
	// be URL-encoded, including the separator.
	case packageurl.TypeNPM:
		name = url.QueryEscape(fmt.Sprintf("%s/%s", purl.Namespace, purl.Name))

	// apk packages are only used by alpine, so the namespace isn't used in the
	// package name for the ecosyste.ms API
	case packageurl.TypeApk:
		break
	}

	return name
}
