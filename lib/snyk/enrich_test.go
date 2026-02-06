package snyk

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog"
	spdx "github.com/spdx/tools-golang/spdx/v2/common"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/parlay/lib/sbom"
)

var (
	//go:embed testdata/numpy_issues.json
	numpyIssues []byte
	//go:embed testdata/pandas_issues.json
	pandasIssues []byte
	//go:embed testdata/no_issues.json
	noIssues []byte
)

func TestEnrichSBOM_CycloneDXWithVulnerabilities(t *testing.T) {
	svc := setupTestEnv(t)

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

	svc.EnrichSBOM(doc)

	require.NotNil(t, bom.Vulnerabilities)
	assert.Len(t, *bom.Vulnerabilities, 1)
	vuln := (*bom.Vulnerabilities)[0]
	assert.Equal(t, "pkg:pypi/numpy@1.16.0", vuln.BOMRef)
	assert.Equal(t, "SNYK-PYTHON-NUMPY-73513", vuln.ID)

	assert.NotNil(t, vuln.Ratings)
	assert.Len(t, *vuln.Ratings, 4)
	assert.Equal(t, (*vuln.Ratings)[0].Source, &cdx.Source{Name: "Snyk", URL: "https://security.snyk.io"})
	assert.Equal(t, (*vuln.Ratings)[0].Method, cdx.ScoringMethodCVSSv31)
	assert.Equal(t, (*vuln.Ratings)[1].Source, &cdx.Source{Name: "NVD"})
	assert.Equal(t, (*vuln.Ratings)[1].Method, cdx.ScoringMethodCVSSv3)
}

func TestEnrichSBOM_CycloneDXDeduplicatesRequests(t *testing.T) {
	var numRequests int32
	mux := http.NewServeMux()
	mux.HandleFunc(
		"GET /rest/self",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, selfBody)
		})
	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/{purl}/issues",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&numRequests, 1)
			respond(w, numpyIssues)
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := DefaultConfig()
	cfg.APIToken = "asdf"
	cfg.SnykAPIURL = srv.URL

	logger := zerolog.Nop()
	svc := NewService(cfg, &logger)

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:pypi/numpy@1.16.0",
				Name:       "numpy",
				Version:    "1.16.0",
				PackageURL: "pkg:pypi/numpy@1.16.0",
			},
			{
				BOMRef:     "pkg:pypi/numpy@1.16.0#dup",
				Name:       "numpy",
				Version:    "1.16.0",
				PackageURL: "pkg:pypi/numpy@1.16.0",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	svc.EnrichSBOM(doc)

	assert.Equal(t, int32(1), atomic.LoadInt32(&numRequests))
	require.NotNil(t, bom.Vulnerabilities)
	vulnByRef := map[string]int{}
	for _, vuln := range *bom.Vulnerabilities {
		vulnByRef[vuln.BOMRef]++
	}
	assert.Greater(t, vulnByRef["pkg:pypi/numpy@1.16.0"], 0)
	assert.Greater(t, vulnByRef["pkg:pypi/numpy@1.16.0#dup"], 0)
}

func TestEnrichSBOM_CycloneDXExternalRefs(t *testing.T) {
	svc := setupTestEnv(t)

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

	svc.EnrichSBOM(doc)

	require.NotNil(t, bom.Components)
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
	svc := setupTestEnv(t)

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

	svc.EnrichSBOM(doc)

	require.NotNil(t, bom.Components)
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
	svc := setupTestEnv(t)

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

	svc.EnrichSBOM(doc)

	require.NotNil(t, bom.Vulnerabilities)
	assert.Len(t, *bom.Vulnerabilities, 2)
}

func TestEnrichSBOM_CycloneDXWithoutVulnerabilities(t *testing.T) {
	svc := setupTestEnv(t)

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

	svc.EnrichSBOM(doc)

	assert.Nil(t, bom.Vulnerabilities, "should not extend vulnerabilities if there are none")
}

func TestEnrichSBOM_SPDXWithVulnerabilities(t *testing.T) {
	svc := setupTestEnv(t)

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

	svc.EnrichSBOM(doc)

	vulnRef := bom.Packages[0].PackageExternalReferences[3]
	assert.Equal(t, "SECURITY", vulnRef.Category)
	assert.Equal(t, "advisory", vulnRef.RefType)
	assert.Equal(t, "https://security.snyk.io/vuln/SNYK-PYTHON-NUMPY-73513", vulnRef.Locator)
	assert.Equal(t, "Arbitrary Code Execution", vulnRef.ExternalRefComment)
}

func TestEnrichSBOM_SPDXDeduplicatesRequests(t *testing.T) {
	var numRequests int32
	mux := http.NewServeMux()
	mux.HandleFunc(
		"GET /rest/self",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, selfBody)
		})
	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/{purl}/issues",
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&numRequests, 1)
			respond(w, numpyIssues)
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := DefaultConfig()
	cfg.APIToken = "asdf"
	cfg.SnykAPIURL = srv.URL

	logger := zerolog.Nop()
	svc := NewService(cfg, &logger)

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
			{
				PackageSPDXIdentifier: "pkg:pypi/numpy@1.16.0-dup",
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

	svc.EnrichSBOM(doc)

	assert.Equal(t, int32(1), atomic.LoadInt32(&numRequests))
	expectedLocator := "https://security.snyk.io/vuln/SNYK-PYTHON-NUMPY-73513"
	for _, pkg := range bom.Packages {
		hasVulnRef := false
		for _, ref := range pkg.PackageExternalReferences {
			if ref.Category == spdx.CategorySecurity &&
				ref.RefType == "advisory" &&
				ref.Locator == expectedLocator {
				hasVulnRef = true
				break
			}
		}
		assert.Truef(t, hasVulnRef, "expected vulnerability reference for %s", pkg.PackageSPDXIdentifier)
	}
}

func TestEnrichSBOM_SPDXExternalRefs(t *testing.T) {
	svc := setupTestEnv(t)

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

	svc.EnrichSBOM(doc)

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

func setupTestEnv(t *testing.T) Service {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc(
		"GET /rest/self",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, selfBody)
		})

	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/{purl}/issues",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, noIssues)
		})

	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/pkg%3Apypi%2Fnumpy%401.16.0/issues",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, numpyIssues)
		})

	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/pkg%3Apypi%2Fpandas%400.15.0/issues",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, pandasIssues)
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := DefaultConfig()
	cfg.APIToken = "asdf"
	cfg.SnykAPIURL = srv.URL

	logger := zerolog.Nop()
	svc := NewService(cfg, &logger)

	return svc
}

func respond(w http.ResponseWriter, data []byte) {
	w.Header().Set("content-type", "application/vnd.api+json")
	if _, err := w.Write(data); err != nil {
		panic(err)
	}
}
