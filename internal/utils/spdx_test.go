package utils_test

import (
	"testing"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/internal/utils"

	"github.com/stretchr/testify/assert"
)

func TestGetLicensesFromEcosystemsLicense(t *testing.T) {
	versionedLicenses := "GPLv2,MIT"
	empty := ""

	for name, tc := range map[string]struct {
		pkgVersionData *packages.VersionWithDependencies
		pkgData        *packages.Package
		want           []string
	}{
		"version licenses win": {
			pkgVersionData: &packages.VersionWithDependencies{Licenses: &versionedLicenses},
			pkgData:        &packages.Package{NormalizedLicenses: []string{"Apache-2.0"}},
			want:           []string{"GPLv2", "MIT"},
		},
		"falls back to the package licenses": {
			pkgVersionData: &packages.VersionWithDependencies{},
			pkgData:        &packages.Package{NormalizedLicenses: []string{"Apache-2.0"}},
			want:           []string{"Apache-2.0"},
		},
		"no package data": {
			pkgVersionData: &packages.VersionWithDependencies{Licenses: &versionedLicenses},
			pkgData:        &packages.Package{},
			want:           []string{"GPLv2", "MIT"},
		},
		"no data at all": {
			want: nil,
		},
		"empty licenses": {
			pkgVersionData: &packages.VersionWithDependencies{Licenses: &empty},
			pkgData:        &packages.Package{NormalizedLicenses: []string{}},
			want:           nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, utils.GetLicensesFromEcosystemsLicense(tc.pkgVersionData, tc.pkgData))
		})
	}
}
