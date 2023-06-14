package ecosystems

import (
	"errors"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func enrichSPDXDoc(bom *spdx.Document) {
	packages := bom.Packages

	for _, pkg := range packages {
		purl, err := extractPurl(pkg)
		if err != nil {
			continue
		}

		resp, err := GetPackageData(*purl) // TODO: change signature to pass in pointer
		if err != nil {
			continue
		}

		pkgData := resp.JSON200
		if pkgData == nil {
			continue
		}

		enrichSPDX_Description(pkg, pkgData)
		enrichSPDX_License(pkg, pkgData)
		enrichSPDX_Homepage(pkg, pkgData)
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

func enrichSPDX_License(pkg *v2_3.Package, data *packages.Package) {
	if len(data.NormalizedLicenses) == 1 {
		pkg.PackageLicenseConcluded = data.NormalizedLicenses[0]
	} else if len(data.NormalizedLicenses) > 1 {
		pkg.PackageLicenseConcluded = fmt.Sprintf("(%s)", strings.Join(data.NormalizedLicenses, " OR "))
	}
}

func enrichSPDX_Homepage(pkg *v2_3.Package, data *packages.Package) {
	pkg.PackageHomePage = *data.Homepage
}

func enrichSPDX_Description(pkg *v2_3.Package, data *packages.Package) {
	pkg.PackageDescription = *data.Description
}
