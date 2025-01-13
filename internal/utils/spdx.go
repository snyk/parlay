package utils

import (
	"fmt"
	"slices"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
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

func GetSPDXLicensesFromEcosystemsLicense(data *packages.Version) (valid []string, invalid []string) {
	if data == nil || data.Licenses == nil || *data.Licenses == "" {
		return nil, nil
	}
	licenses := strings.Split(*data.Licenses, ",")
	_, invalid = spdxexp.ValidateLicenses(licenses)
	for _, lic := range licenses {
		if !slices.Contains(invalid, lic) {
			valid = append(valid, lic)
		}
	}
	return valid, invalid
}
