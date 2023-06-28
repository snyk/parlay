package utils

import (
	"fmt"

	"github.com/package-url/packageurl-go"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
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
