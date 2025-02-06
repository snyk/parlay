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

func GetSPDXLicenseExpressionFromEcosystemsLicense(pkgVersionData *packages.VersionWithDependencies, pkgData *packages.Package) string {
	licenses := ""
	if pkgVersionData != nil && pkgVersionData.Licenses != nil && *pkgVersionData.Licenses != "" {
		licenses = *pkgVersionData.Licenses
	} else if pkgData != nil && pkgData.Licenses != nil && *pkgData.Licenses != "" {
		licenses = *pkgData.Licenses
	}
	if licenses == "" {
		return ""
	}
	return fmt.Sprintf("(%s)", strings.Join(strings.Split(licenses, ","), " OR "))
}
