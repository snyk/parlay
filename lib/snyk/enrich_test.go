package snyk

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jarcoal/httpmock"
	"github.com/rs/zerolog"
	spdx "github.com/spdx/tools-golang/spdx/v2/common"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/parlay/lib/sbom"
)

func TestEnrichSBOM_CycloneDXWithVulnerabilities(t *testing.T) {
	teardown := setupTestEnv(t)
	defer teardown()

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:pypi/numpy@1.16.0",
				Name:       "numpy",
				Version:    "1.16.0",
				PackageURL: "pkg:pypi/numpy@1.16.0",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, logger)

	assert.NotNil(t, bom.Vulnerabilities)
	assert.Len(t, *bom.Vulnerabilities, 1)
	vuln := (*bom.Vulnerabilities)[0]
	assert.Equal(t, "pkg:pypi/numpy@1.16.0", vuln.BOMRef)
	assert.Equal(t, "SNYK-PYTHON-NUMPY-73513", vuln.ID)
}

func TestEnrichSBOM_CycloneDXWithoutVulnerabilities(t *testing.T) {
	teardown := setupTestEnv(t)
	defer teardown()

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:pypi/werkzeug@2.2.3",
				Name:       "werkzeug",
				Version:    "2.2.3",
				PackageURL: "pkg:pypi/werkzeug@2.2.3",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, logger)

	assert.Nil(t, bom.Vulnerabilities, "should not extend vulnerabilities if there are none")
}

func TestEnrichSBOM_SPDXWithVulnerabilities(t *testing.T) {
	teardown := setupTestEnv(t)
	defer teardown()

	bom := &spdx_2_3.Document{
		Packages: []*spdx_2_3.Package{
			{
				PackageSPDXIdentifier: "pkg:pypi/numpy@1.16.0",
				PackageName:           "numpy",
				PackageVersion:        "1.16.0",
				PackageExternalReferences: []*spdx_2_3.PackageExternalReference{
					{
						Category: spdx.CategoryPackageManager,
						RefType:  "purl",
						Locator:  "pkg:pypi/numpy@1.16.0",
					},
				},
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, logger)

	vulnRef := bom.Packages[0].PackageExternalReferences[1]
	assert.Equal(t, "SECURITY", vulnRef.Category)
	assert.Equal(t, "advisory", vulnRef.RefType)
	assert.Equal(t, "https://security.snyk.io/vuln/SNYK-PYTHON-NUMPY-73513", vulnRef.Locator)
	assert.Equal(t, "Arbitrary Code Execution", vulnRef.ExternalRefComment)
}

func setupTestEnv(t *testing.T) func() {
	t.Helper()

	t.Setenv("SNYK_TOKEN", "asdf")

	httpmock.Activate()
	httpmock.RegisterResponder(
		"GET",
		`=~^https://api\.snyk\.io/rest/self`,
		httpmock.NewJsonResponderOrPanic(200, httpmock.File("testdata/self.json")),
	)
	httpmock.RegisterResponder(
		"GET",
		`=~^https://api\.snyk\.io/rest/orgs/[a-z0-9-]+/packages/pkg%3Apypi%2Fnumpy%401.16.0/issues`,
		httpmock.NewJsonResponderOrPanic(200, httpmock.File("testdata/numpy_issues.json")),
	)
	httpmock.RegisterResponder(
		"GET",
		`=~^https://api\.snyk\.io/rest/orgs/[a-z0-9-]+/packages/.*/issues`,
		httpmock.NewJsonResponderOrPanic(200, httpmock.File("testdata/no_issues.json")),
	)

	return func() {
		httpmock.DeactivateAndReset()
	}
}
