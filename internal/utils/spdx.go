package utils

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/snyk/parlay/ecosystems/packages"
)

func GetPurlFromSPDXPackage(pkg *spdx_2_3.Package) (*packageurl.PackageURL, error) {
	var p string

	for _, ref := range pkg.PackageExternalReferences {
		if ref.RefType == "purl" {
			p = ref.Locator
			break
		}
	}

	if p == "" {
		return nil, fmt.Errorf("no purl on package %s", pkg.PackageName)
	}

	purl, err := packageurl.FromString(p)
	if err != nil {
		return nil, err
	}

	return &purl, nil
}

// GetLicensesFromEcosystemsLicense reads the license strings ecosyste.ms holds
// for a package version, falling back to the ones for the package itself.
//
// ponytail: the versioned field is a comma separated list, so a single license
// name containing a comma splits into two. Rejoining the fragments needs a
// heuristic; capturing them verbatim as separate LicenseRefs is good enough.
func GetLicensesFromEcosystemsLicense(pkgVersionData *packages.VersionWithDependencies, pkgData *packages.Package) []string {
	if pkgVersionData != nil && pkgVersionData.Licenses != nil && *pkgVersionData.Licenses != "" {
		return strings.Split(*pkgVersionData.Licenses, ",")
	} else if pkgData != nil && len(pkgData.NormalizedLicenses) > 0 {
		return pkgData.NormalizedLicenses
	}
	return nil
}
