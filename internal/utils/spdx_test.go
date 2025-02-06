package utils_test

import (
	"testing"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/internal/utils"

	"github.com/stretchr/testify/assert"
)

func TestGetSPDXLicenseExpressionFromEcosystemsLicense(t *testing.T) {
	assert := assert.New(t)
	versionedLicenses := "GPLv2,MIT"
	pkgVersionData := packages.VersionWithDependencies{Licenses: &versionedLicenses}
	latestLicenses := []string{"Apache-2.0"}
	pkgData := packages.Package{NormalizedLicenses: latestLicenses}
	expression := utils.GetLicenseExpressionFromEcosystemsLicense(&pkgVersionData, &pkgData)
	assert.Equal("(GPLv2 OR MIT)", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_NoData(t *testing.T) {
	assert := assert.New(t)
	expression := utils.GetLicenseExpressionFromEcosystemsLicense(nil, nil)
	assert.Equal("", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_NoVersionedData(t *testing.T) {
	assert := assert.New(t)
	pkgVersionData := packages.VersionWithDependencies{}
	latestLicenses := []string{"Apache-2.0"}
	pkgData := packages.Package{NormalizedLicenses: latestLicenses}
	expression := utils.GetLicenseExpressionFromEcosystemsLicense(&pkgVersionData, &pkgData)
	assert.Equal("(Apache-2.0)", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_NoLatestData(t *testing.T) {
	assert := assert.New(t)
	versionedLicenses := "GPLv2,MIT"
	pkgVersionData := packages.VersionWithDependencies{Licenses: &versionedLicenses}
	pkgData := packages.Package{}
	expression := utils.GetLicenseExpressionFromEcosystemsLicense(&pkgVersionData, &pkgData)
	assert.Equal("(GPLv2 OR MIT)", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_NoLicenses(t *testing.T) {
	assert := assert.New(t)
	pkgVersionData := packages.VersionWithDependencies{}
	pkgData := packages.Package{}
	expression := utils.GetLicenseExpressionFromEcosystemsLicense(&pkgVersionData, &pkgData)
	assert.Equal("", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_EmptyLicenses(t *testing.T) {
	assert := assert.New(t)
	versionedLicenses := ""
	pkgVersionData := packages.VersionWithDependencies{Licenses: &versionedLicenses}
	latestLicenses := []string{}
	pkgData := packages.Package{NormalizedLicenses: latestLicenses}
	expression := utils.GetLicenseExpressionFromEcosystemsLicense(&pkgVersionData, &pkgData)
	assert.Equal("", expression)
}
