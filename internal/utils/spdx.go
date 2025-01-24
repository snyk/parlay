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

func GetSPDXLicenseExpressionFromEcosystemsLicense(data *packages.VersionWithDependencies) string {
	if data == nil || data.Licenses == nil || *data.Licenses == "" {
		return ""
	}
	return fmt.Sprintf("(%s)", strings.Join(strings.Split(*data.Licenses, ","), " OR "))
}
