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
	//go:embed testdata/jinja2_issues_no_problems.json
	jinja2IssuesNoProblems []byte
	//go:embed testdata/urllib3_issues_no_slots.json
	urllib3IssuesNoSlots []byte
	//go:embed testdata/pyyaml_issues_bare_severity.json
	pyyamlIssuesBareSeverity []byte
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

func TestEnrichSBOM_CycloneDXIssueWithoutProblems(t *testing.T) {
	// problems is optional in the API spec (specs/snyk.json lists no required attributes), and an
	// issue with no CVE or CWE assigned yet comes back without it. The SPDX path already records
	// such an issue, so CycloneDX must not drop it.
	svc := setupTestEnv(t)

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:pypi/jinja2@2.11.0",
				Name:       "jinja2",
				Version:    "2.11.0",
				PackageURL: "pkg:pypi/jinja2@2.11.0",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	svc.EnrichSBOM(doc)

	require.NotNil(t, bom.Vulnerabilities, "issue without problems was dropped from the BOM")
	assert.Len(t, *bom.Vulnerabilities, 1)
	vuln := (*bom.Vulnerabilities)[0]
	assert.Equal(t, "pkg:pypi/jinja2@2.11.0", vuln.BOMRef)
	assert.Equal(t, "SNYK-PYTHON-JINJA2-1012994", vuln.ID)
	assert.Equal(t, "Sandbox Bypass", vuln.Description)

	require.NotNil(t, vuln.Ratings)
	assert.Len(t, *vuln.Ratings, 1)
	assert.Equal(t, cdx.SeverityHigh, (*vuln.Ratings)[0].Severity)
}

func TestEnrichSBOM_CycloneDXIssueWithoutSlots(t *testing.T) {
	// slots is optional too, so reading Slots.References unconditionally panics on an issue that
	// carries problems but no slots
	svc := setupTestEnv(t)

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:pypi/urllib3@1.25.8",
				Name:       "urllib3",
				Version:    "1.25.8",
				PackageURL: "pkg:pypi/urllib3@1.25.8",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	svc.EnrichSBOM(doc)

	require.NotNil(t, bom.Vulnerabilities)
	assert.Len(t, *bom.Vulnerabilities, 1)
	vuln := (*bom.Vulnerabilities)[0]
	assert.Equal(t, "SNYK-PYTHON-URLLIB3-1014645", vuln.ID)
	require.NotNil(t, vuln.CWEs)
	assert.Equal(t, []int{93}, *vuln.CWEs)
	require.NotNil(t, vuln.References)
	assert.Equal(t, "CVE-2020-26137", (*vuln.References)[0].ID)
	assert.Nil(t, vuln.Advisories)
}

func TestEnrichSBOM_CycloneDXSeverityWithoutLevelVersionOrVector(t *testing.T) {
	// Severity3 has no required fields either, so level, version and vector can all be absent.
	// Those feed levelToCdxSeverity, versionToCdxMethod and rating.Vector, which dereferenced them
	// unconditionally.
	svc := setupTestEnv(t)

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:pypi/pyyaml@5.3",
				Name:       "pyyaml",
				Version:    "5.3",
				PackageURL: "pkg:pypi/pyyaml@5.3",
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}

	svc.EnrichSBOM(doc)

	require.NotNil(t, bom.Vulnerabilities)
	assert.Len(t, *bom.Vulnerabilities, 1)
	vuln := (*bom.Vulnerabilities)[0]
	assert.Equal(t, "SNYK-PYTHON-PYYAML-590151", vuln.ID)

	require.NotNil(t, vuln.Ratings)
	assert.Len(t, *vuln.Ratings, 1)
	rating := (*vuln.Ratings)[0]
	assert.Equal(t, cdx.SeverityUnknown, rating.Severity)
	assert.Equal(t, cdx.ScoringMethodOther, rating.Method)
	assert.Empty(t, rating.Vector)
	require.NotNil(t, rating.Score)
	assert.InDelta(t, 9.8, *rating.Score, 0.001)
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

	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/pkg%3Apypi%2Fjinja2%402.11.0/issues",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, jinja2IssuesNoProblems)
		})

	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/pkg%3Apypi%2Furllib3%401.25.8/issues",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, urllib3IssuesNoSlots)
		})

	mux.HandleFunc(
		"GET /rest/orgs/{org_id}/packages/pkg%3Apypi%2Fpyyaml%405.3/issues",
		func(w http.ResponseWriter, r *http.Request) {
			respond(w, pyyamlIssuesBareSeverity)
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
