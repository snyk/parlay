package utils_test

import (
	"testing"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/internal/utils"

	"github.com/stretchr/testify/assert"
)

func TestGetSPDXLicenseExpressionFromEcosystemsLicense(t *testing.T) {
	assert := assert.New(t)
	licenses := "GPLv2,MIT"
	data := packages.VersionWithDependencies{Licenses: &licenses}
	expression := utils.GetSPDXLicenseExpressionFromEcosystemsLicense(&data)
	assert.Equal("(GPLv2 OR MIT)", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_NoData(t *testing.T) {
	assert := assert.New(t)
	expression := utils.GetSPDXLicenseExpressionFromEcosystemsLicense(nil)
	assert.Equal("", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_NoLicenses(t *testing.T) {
	assert := assert.New(t)
	data := packages.VersionWithDependencies{}
	expression := utils.GetSPDXLicenseExpressionFromEcosystemsLicense(&data)
	assert.Equal("", expression)
}

func TestGetSPDXLicenseExpressionFromEcosystemsLicense_EmptyLicenses(t *testing.T) {
	assert := assert.New(t)
	licenses := ""
	data := packages.VersionWithDependencies{Licenses: &licenses}
	expression := utils.GetSPDXLicenseExpressionFromEcosystemsLicense(&data)
	assert.Equal("", expression)
}
