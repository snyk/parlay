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
	"errors"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/snyk/parlay/ecosystems/packages"
)

func enrichSPDX(bom *spdx.Document, logger *zerolog.Logger) {
	packages := bom.Packages

	logger.Debug().Msgf("Detected %d packages", len(packages))

	for _, pkg := range packages {
		purl, err := extractPurl(pkg)
		if err != nil {
			continue
		}

		resp, err := GetPackageData(*purl)
		if err != nil {
			continue
		}

		pkgData := resp.JSON200
		if pkgData == nil {
			continue
		}

		enrichSPDXDescription(pkg, pkgData)
		enrichSPDXLicense(pkg, pkgData)
		enrichSPDXHomepage(pkg, pkgData)
	}
}

func extractPurl(pkg *v2_3.Package) (*packageurl.PackageURL, error) {
	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType != "purl" {
			continue
		}
		purl, err := packageurl.FromString(ref.Locator)
		if err != nil {
			return nil, err
		}
		return &purl, nil
	}
	return nil, errors.New("no purl found on SPDX package")
}

func enrichSPDXLicense(pkg *v2_3.Package, data *packages.Package) {
	if len(data.NormalizedLicenses) == 1 {
		pkg.PackageLicenseConcluded = data.NormalizedLicenses[0]
	} else if len(data.NormalizedLicenses) > 1 {
		pkg.PackageLicenseConcluded = fmt.Sprintf("(%s)", strings.Join(data.NormalizedLicenses, " OR "))
	}
}

func enrichSPDXHomepage(pkg *v2_3.Package, data *packages.Package) {
	if data.Homepage == nil {
		return
	}
	pkg.PackageHomePage = *data.Homepage
}

func enrichSPDXDescription(pkg *v2_3.Package, data *packages.Package) {
	if data.Description == nil {
		return
	}
	pkg.PackageDescription = *data.Description
}
