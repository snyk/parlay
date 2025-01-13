package utils_test

import (
	"testing"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/internal/utils"

	"github.com/stretchr/testify/assert"
)

func TestGetSPDXLicensesFromEcosystemsLicense(t *testing.T) {
	assert := assert.New(t)
	licenses := "MIT,AGPL-3.0-or-later,Unknown,AGPL-1.0"
	data := packages.Version{Licenses: &licenses}

	validLics, invalidLics := utils.GetSPDXLicensesFromEcosystemsLicense(&data)

	assert.Len(validLics, 3)
	assert.Equal(validLics[0], "MIT")
	assert.Equal(validLics[1], "AGPL-3.0-or-later")
	assert.Equal(validLics[2], "AGPL-1.0")

	assert.Len(invalidLics, 1)
	assert.Equal(invalidLics[0], "Unknown")
}

func TestGetSPDXLicensesFromEcosystemsLicense_NoData(t *testing.T) {
	assert := assert.New(t)

	validLics, invalidLics := utils.GetSPDXLicensesFromEcosystemsLicense(nil)

	assert.Len(validLics, 0)
	assert.Len(invalidLics, 0)
}

func TestGetSPDXLicensesFromEcosystemsLicense_NoLicenses(t *testing.T) {
	assert := assert.New(t)
	data := packages.Version{Licenses: nil}

	validLics, invalidLics := utils.GetSPDXLicensesFromEcosystemsLicense(&data)

	assert.Len(validLics, 0)
	assert.Len(invalidLics, 0)
}

func TestGetSPDXLicensesFromEcosystemsLicense_EmptyLicenses(t *testing.T) {
	assert := assert.New(t)
	licenses := ""
	data := packages.Version{Licenses: &licenses}

	validLics, invalidLics := utils.GetSPDXLicensesFromEcosystemsLicense(&data)

	assert.Len(validLics, 0)
	assert.Len(invalidLics, 0)
}
