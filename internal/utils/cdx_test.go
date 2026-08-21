package utils_test

import (
	"testing"

	"github.com/snyk/parlay/internal/utils"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestDiscoverCDXComponents(t *testing.T) {
	assert := assert.New(t)

	bom := &cdx.BOM{
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				Name: "MetaComp",
			},
		},
		Components: &[]cdx.Component{
			{
				Name: "Parent",
				Components: &[]cdx.Component{
					{Name: "Child"},
				},
			},
		},
	}
	result := utils.DiscoverCDXComponents(bom)

	assert.Equal(len(result), 3)
}

func TestCDXLicenses(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []utils.License
		want *cdx.Licenses
	}{
		"nothing in, nothing out": {
			in:   nil,
			want: nil,
		},
		"all valid becomes one expression": {
			in:   []utils.License{{SPDXID: "MIT"}, {SPDXID: "Apache-2.0"}},
			want: &cdx.Licenses{{Expression: "(MIT OR Apache-2.0)"}},
		},
		"any invalid falls back to a list": {
			in: []utils.License{
				{SPDXID: "MIT"},
				{SPDXID: "LicenseRef-Eclipse-Public-License-1.0", Raw: "Eclipse Public License 1.0"},
			},
			want: &cdx.Licenses{
				{License: &cdx.License{ID: "MIT"}},
				{License: &cdx.License{Name: "Eclipse Public License 1.0"}},
			},
		},
		// CycloneDX validates license ids against a closed list, which carries
		// only the six grandfathered "+" identifiers, so an "or later" license
		// has to be named rather than identified.
		"or later is named, it is not a CycloneDX license id": {
			in: []utils.License{
				{SPDXID: "Apache-2.0+"},
				{SPDXID: "LicenseRef-Proprietary", Raw: "Proprietary"},
			},
			want: &cdx.Licenses{
				{License: &cdx.License{Name: "Apache-2.0+"}},
				{License: &cdx.License{Name: "Proprietary"}},
			},
		},
		"a grandfathered or later is still a license id": {
			in: []utils.License{
				{SPDXID: "GPL-2.0+"},
				{SPDXID: "LicenseRef-Proprietary", Raw: "Proprietary"},
			},
			want: &cdx.Licenses{
				{License: &cdx.License{ID: "GPL-2.0+"}},
				{License: &cdx.License{Name: "Proprietary"}},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, utils.CDXLicenses(tc.in))
		})
	}
}
