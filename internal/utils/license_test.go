package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/parlay/internal/utils"
)

func TestClassifyLicenses(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []string
		want []utils.License
	}{
		"valid identifier": {
			in:   []string{"MIT"},
			want: []utils.License{{SPDXID: "MIT"}},
		},
		"normalizes case": {
			in:   []string{"apache-2.0"},
			want: []utils.License{{SPDXID: "Apache-2.0"}},
		},
		"trims whitespace": {
			in:   []string{" MIT "},
			want: []utils.License{{SPDXID: "MIT"}},
		},
		"valid expression passes through": {
			in:   []string{"(MIT OR Apache-2.0)"},
			want: []utils.License{{SPDXID: "MIT OR Apache-2.0"}},
		},
		"exception passes through": {
			in:   []string{"GPL-2.0-only WITH Classpath-exception-2.0"},
			want: []utils.License{{SPDXID: "GPL-2.0-only WITH Classpath-exception-2.0"}},
		},
		"invalid becomes a ref": {
			in: []string{"The Apache Software License, Version 2.0"},
			want: []utils.License{{
				SPDXID: "LicenseRef-The-Apache-Software-License-Version-2.0",
				Raw:    "The Apache Software License, Version 2.0",
			}},
		},
		"mixed keeps the valid identifiers": {
			in: []string{"MIT", "Eclipse Public License 1.0"},
			want: []utils.License{
				{SPDXID: "MIT"},
				{SPDXID: "LicenseRef-Eclipse-Public-License-1.0", Raw: "Eclipse Public License 1.0"},
			},
		},
		"incoming ref is captured as extracted text": {
			in: []string{"LicenseRef-Proprietary"},
			want: []utils.License{{
				SPDXID: "LicenseRef-Proprietary",
				Raw:    "LicenseRef-Proprietary",
			}},
		},
		"NOASSERTION is dropped, it cannot be joined into an expression": {
			in:   []string{"NOASSERTION", "MIT"},
			want: []utils.License{{SPDXID: "MIT"}},
		},
		"repeats collapse": {
			in:   []string{"MIT", "MIT"},
			want: []utils.License{{SPDXID: "MIT"}},
		},
		"repeats differing only in case collapse": {
			in:   []string{"MIT", "mit"},
			want: []utils.License{{SPDXID: "MIT"}},
		},
		"blanks are dropped": {
			in:   []string{"", "  "},
			want: []utils.License{},
		},
		"unidentifiable strings are dropped": {
			in:   []string{"???"},
			want: []utils.License{},
		},
		"nothing in, nothing out": {
			in:   nil,
			want: []utils.License{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, utils.ClassifyLicenses(tc.in))
		})
	}
}

func TestLicenseExpression(t *testing.T) {
	assert.Equal(t, "", utils.LicenseExpression(nil))
	assert.Equal(t, "MIT", utils.LicenseExpression([]string{"MIT"}))
	assert.Equal(t,
		"(MIT OR LicenseRef-Weird)",
		utils.LicenseExpression([]string{"MIT", "LicenseRef-Weird"}),
	)
}

func TestDisambiguateLicenseRef(t *testing.T) {
	id := "LicenseRef-Apache-2.0-MIT"

	// Two license strings that sanitize to the same identifier must not end up
	// sharing it, or packages get put under a license they are not under.
	assert.NotEqual(t,
		utils.DisambiguateLicenseRef(id, "Apache 2.0/MIT"),
		utils.DisambiguateLicenseRef(id, "Apache 2.0 MIT"),
	)
	assert.Equal(t,
		utils.DisambiguateLicenseRef(id, "Apache 2.0/MIT"),
		utils.DisambiguateLicenseRef(id, "Apache 2.0/MIT"),
	)
	assert.Contains(t, utils.DisambiguateLicenseRef(id, "Apache 2.0/MIT"), id+"-")
}
