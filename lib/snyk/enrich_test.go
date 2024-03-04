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
	EnrichSBOM(doc, &logger)

	assert.NotNil(t, bom.Vulnerabilities)
	assert.Len(t, *bom.Vulnerabilities, 1)
	vuln := (*bom.Vulnerabilities)[0]
	assert.Equal(t, "pkg:pypi/numpy@1.16.0", vuln.BOMRef)
	assert.Equal(t, "SNYK-PYTHON-NUMPY-73513", vuln.ID)
}

func TestEnrichSBOM_CycloneDXExternalRefs(t *testing.T) {
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
	EnrichSBOM(doc, &logger)

	assert.NotNil(t, bom.Components)
	refs := (*bom.Components)[0].ExternalReferences
	assert.Len(t, *refs, 2)

	ref1 := (*refs)[0]
	assert.Equal(t, "https://snyk.io/advisor/python/numpy", ref1.URL)
	assert.Equal(t, "Snyk Advisor", ref1.Comment)
	assert.Equal(t, cdx.ExternalReferenceType("Other"), ref1.Type)

	ref2 := (*refs)[1]
	assert.Equal(t, "https://security.snyk.io/package/pip/numpy", ref2.URL)
	assert.Equal(t, "Snyk Vulnerability DB", ref2.Comment)
	assert.Equal(t, cdx.ExternalReferenceType("Other"), ref2.Type)
}

func TestEnrichSBOM_CycloneDXExternalRefs_WithNamespace(t *testing.T) {
	teardown := setupTestEnv(t)
	defer teardown()

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "@emotion/react@11.11.3",
				Name:       "react",
				Version:    "11.11.3",
				PackageURL: "pkg:npm/%40emotion/react@11.11.3",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	logger := zerolog.Nop()
	EnrichSBOM(doc, &logger)

	assert.NotNil(t, bom.Components)
	refs := (*bom.Components)[0].ExternalReferences
	assert.Len(t, *refs, 2)

	ref1 := (*refs)[0]
	assert.Equal(t, "https://snyk.io/advisor/npm-package/@emotion/react", ref1.URL)
	assert.Equal(t, "Snyk Advisor", ref1.Comment)
	assert.Equal(t, cdx.ExternalReferenceType("Other"), ref1.Type)

	ref2 := (*refs)[1]
	assert.Equal(t, "https://security.snyk.io/package/npm/@emotion%2Freact", ref2.URL)
	assert.Equal(t, "Snyk Vulnerability DB", ref2.Comment)
	assert.Equal(t, cdx.ExternalReferenceType("Other"), ref2.Type)
}

func TestEnrichSBOM_CycloneDXWithVulnerabilities_NestedComponents(t *testing.T) {
	teardown := setupTestEnv(t)
	defer teardown()

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:pypi/pandas@0.15.0",
				Name:       "pandas",
				Version:    "0.15.0",
				PackageURL: "pkg:pypi/pandas@0.15.0",
				Components: &[]cdx.Component{
					{
						BOMRef:     "pkg:pypi/numpy@1.16.0",
						Name:       "numpy",
						Version:    "1.16.0",
						PackageURL: "pkg:pypi/numpy@1.16.0",
					},
				},
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	logger := zerolog.Nop()
	EnrichSBOM(doc, &logger)

	assert.NotNil(t, bom.Vulnerabilities)
	assert.Len(t, *bom.Vulnerabilities, 2)
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
	EnrichSBOM(doc, &logger)

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
	EnrichSBOM(doc, &logger)

	vulnRef := bom.Packages[0].PackageExternalReferences[3]
	assert.Equal(t, "SECURITY", vulnRef.Category)
	assert.Equal(t, "advisory", vulnRef.RefType)
	assert.Equal(t, "https://security.snyk.io/vuln/SNYK-PYTHON-NUMPY-73513", vulnRef.Locator)
	assert.Equal(t, "Arbitrary Code Execution", vulnRef.ExternalRefComment)
}

func TestEnrichSBOM_SPDXExternalRefs(t *testing.T) {
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
	EnrichSBOM(doc, &logger)

	assert.NotNil(t, bom.Packages)
	refs := (*bom.Packages[0]).PackageExternalReferences
	assert.Len(t, refs, 4)

	ref1 := refs[1]
	assert.Equal(t, "https://snyk.io/advisor/python/numpy", ref1.Locator)
	assert.Equal(t, "Snyk Advisor", ref1.ExternalRefComment)
	assert.Equal(t, "advisory", ref1.RefType)
	assert.Equal(t, spdx.CategoryOther, ref1.Category)

	ref2 := refs[2]
	assert.Equal(t, "https://security.snyk.io/package/pip/numpy", ref2.Locator)
	assert.Equal(t, "Snyk Vulnerability DB", ref2.ExternalRefComment)
	assert.Equal(t, "url", ref2.RefType)
	assert.Equal(t, spdx.CategoryOther, ref2.Category)
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
		`=~^https://api\.snyk\.io/rest/orgs/[a-z0-9-]+/packages/pkg%3Apypi%2Fpandas%400.15.0/issues`,
		httpmock.NewJsonResponderOrPanic(200, httpmock.File("testdata/pandas_issues.json")),
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
