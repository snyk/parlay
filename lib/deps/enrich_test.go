/*
 * © 2023 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package deps

import (
	"net/http"
	"regexp"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jarcoal/httpmock"
	"github.com/rs/zerolog"
	"github.com/spdx/tools-golang/spdx"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/parlay/lib/sbom"
)

const depsDevAPIURL = "https://api.deps.dev/v3/projects/github.com%2Fsnyk%2Fparlay"

func TestEnrichSBOM_CycloneDX(t *testing.T) {
	teardown := setupDepsDevAPIMock(t)
	defer teardown()

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				Name: "test-package",
				ExternalReferences: &[]cdx.ExternalReference{
					{
						Type: "vcs",
						URL:  "https://github.com/snyk/parlay",
					},
				},
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	assert.NotNil(t, bom.Components)
	component := (*bom.Components)[0]

	assert.NotNil(t, component.Properties)

	hasOpenIssues := false
	hasStars := false
	hasScorecard := false

	for _, prop := range *component.Properties {
		switch prop.Name {
		case "deps:open_issues_count":
			hasOpenIssues = true
			assert.Equal(t, "42", prop.Value)
		case "deps:stars_count":
			hasStars = true
			assert.Equal(t, "1250", prop.Value)
		case "deps:scorecard":
			hasScorecard = true
			assert.Equal(t, "7.50", prop.Value)
		}
	}

	assert.True(t, hasOpenIssues, "Should have open issues count")
	assert.True(t, hasStars, "Should have stars count")
	assert.True(t, hasScorecard, "Should have scorecard score")
}

func TestEnrichSBOM_SPDX(t *testing.T) {
	teardown := setupDepsDevAPIMock(t)
	defer teardown()

	pkg := &spdx_2_3.Package{
		PackageName:           "test-package",
		PackageSPDXIdentifier: "SPDXRef-Package",
		PackageExternalReferences: []*spdx_2_3.PackageExternalReference{
			{
				Category: "PACKAGE-MANAGER",
				RefType:  "vcs",
				Locator:  "https://github.com/snyk/parlay",
			},
		},
	}

	doc := &spdx.Document{
		Packages: []*spdx_2_3.Package{pkg},
	}
	sbomDoc := &sbom.SBOMDocument{BOM: doc}
	logger := zerolog.Nop()

	EnrichSBOM(sbomDoc, &logger)

	assert.Greater(t, len(pkg.PackageExternalReferences), 1, "Should have added external references")

	hasOpenIssues := false
	hasStars := false
	hasScorecard := false

	for _, ref := range pkg.PackageExternalReferences {
		switch ref.RefType {
		case "deps:open_issues_count":
			hasOpenIssues = true
			assert.Equal(t, "42", ref.Locator)
		case "deps:stars_count":
			hasStars = true
			assert.Equal(t, "1250", ref.Locator)
		case "deps:scorecard":
			hasScorecard = true
			assert.Equal(t, "7.50", ref.Locator)
		}
	}

	assert.True(t, hasOpenIssues, "Should have open issues count")
	assert.True(t, hasStars, "Should have stars count")
	assert.True(t, hasScorecard, "Should have scorecard score")
}

func TestEnrichSBOM_UnsupportedFormat(t *testing.T) {
	logger := zerolog.Nop()
	doc := &sbom.SBOMDocument{BOM: "unsupported"}

	EnrichSBOM(doc, &logger)
}

func setupDepsDevAPIMock(t *testing.T) func() {
	originalGetRetryClient := getRetryClient

	getRetryClient = func(logger *zerolog.Logger) *http.Client {
		return &http.Client{Transport: httpmock.DefaultTransport}
	}

	httpmock.Activate()

	mockResponse := `{
		"projectKey": {
			"id": "github.com/snyk/parlay"
		},
		"openIssuesCount": 42,
		"starsCount": 1250,
		"forksCount": 28,
		"license": "Apache-2.0",
		"description": "A great tool for SBOMs",
		"homepage": "https://github.com/snyk/parlay",
		"scorecard": {
			"overallScore": 7.5,
			"date": "2023-08-05T00:00:00Z"
		}
	}`

	httpmock.RegisterResponder("GET", depsDevAPIURL,
		httpmock.NewStringResponder(http.StatusOK, mockResponse))

	return func() {
		httpmock.DeactivateAndReset()
		getRetryClient = originalGetRetryClient
	}
}

func TestNormalizeRepoURL(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "https URL",
			input:    "https://github.com/snyk/parlay",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "http URL",
			input:    "http://github.com/snyk/parlay",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "git URL",
			input:    "git://github.com/snyk/parlay",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "SSH URL",
			input:    "git@github.com:snyk/parlay",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "URL with .git suffix",
			input:    "https://github.com/snyk/parlay.git",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "URL with trailing slash",
			input:    "https://github.com/snyk/parlay/",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "Complex case",
			input:    "git@github.com:snyk/parlay.git/",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "URL with extra path segments",
			input:    "https://github.com/snyk/parlay/tree/main/lib",
			expected: "github.com/snyk/parlay",
		},
		{
			name:     "GitLab URL",
			input:    "https://gitlab.com/owner/project.git",
			expected: "gitlab.com/owner/project",
		},
		{
			name:     "Bitbucket URL",
			input:    "git@bitbucket.org:owner/project.git",
			expected: "bitbucket.org/owner/project",
		},
		{
			name:     "Invalid URL fallback",
			input:    "not-a-valid-url/but/has/slashes.git/",
			expected: "not-a-valid-url/but/has/slashes",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeRepoURL(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetRepoDataWithCache(t *testing.T) {
	teardown := setupDepsDevAPIMock(t)
	defer teardown()

	logger := zerolog.Nop()
	cache := newProjectCache()

	project1, err := GetRepoDataWithCache("https://github.com/snyk/parlay", &logger, cache)
	assert.NoError(t, err)
	assert.NotNil(t, project1)
	assert.NotNil(t, project1.OpenIssuesCount)
	assert.Equal(t, 42, *project1.OpenIssuesCount)

	project2, err := GetRepoDataWithCache("https://github.com/snyk/parlay", &logger, cache)
	assert.NoError(t, err)
	assert.NotNil(t, project2)
	assert.Equal(t, project1, project2)

	info := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, info["GET "+depsDevAPIURL])
}

func TestGetRepoData_NilValues(t *testing.T) {
	originalGetRetryClient := getRetryClient

	getRetryClient = func(logger *zerolog.Logger) *http.Client {
		return &http.Client{Transport: httpmock.DefaultTransport}
	}
	defer func() {
		getRetryClient = originalGetRetryClient
	}()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Simulate BitBucket response with nil values
	mockResponse := `{
		"projectKey": {
			"id": "bitbucket.org/owner/repo"
		},
		"openIssuesCount": null,
		"starsCount": null,
		"forksCount": null,
		"license": "MIT",
		"description": null,
		"homepage": null,
		"scorecard": null
	}`

	httpmock.RegisterResponder("GET", "https://api.deps.dev/v3/projects/bitbucket.org%2Fowner%2Frepo",
		httpmock.NewStringResponder(http.StatusOK, mockResponse))

	logger := zerolog.Nop()
	project, err := GetRepoDataWithLogger("https://bitbucket.org/owner/repo", &logger)

	assert.NoError(t, err)
	assert.NotNil(t, project)
	assert.Nil(t, project.OpenIssuesCount)
	assert.Nil(t, project.StarsCount)
	assert.Nil(t, project.ForksCount)
	assert.NotNil(t, project.License)
	assert.Equal(t, "MIT", *project.License)
	assert.Nil(t, project.Description)
	assert.Nil(t, project.Homepage)
	assert.Nil(t, project.Scorecard)
}

func TestGetRepoData_ServerError(t *testing.T) {
	originalGetRetryClient := getRetryClient

	getRetryClient = func(logger *zerolog.Logger) *http.Client {
		return &http.Client{Transport: httpmock.DefaultTransport}
	}
	defer func() {
		getRetryClient = originalGetRetryClient
	}()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", depsDevAPIURL,
		httpmock.NewStringResponder(http.StatusInternalServerError, "Server error"))

	logger := zerolog.Nop()
	project, err := GetRepoDataWithLogger("https://github.com/snyk/parlay", &logger)

	assert.Error(t, err)
	assert.Nil(t, project)
}

func TestGetRepoDataNotFound(t *testing.T) {
	originalGetRetryClient := getRetryClient

	getRetryClient = func(logger *zerolog.Logger) *http.Client {
		return &http.Client{Transport: httpmock.DefaultTransport}
	}
	defer func() {
		getRetryClient = originalGetRetryClient
	}()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://api.deps.dev/v3/projects/github.com%2Fnonexistent%2Frepo",
		httpmock.NewStringResponder(http.StatusNotFound, "Not found"))

	logger := zerolog.Nop()
	project, err := GetRepoDataWithLogger("https://github.com/nonexistent/repo", &logger)

	assert.Error(t, err)
	assert.Nil(t, project)
	assert.Contains(t, err.Error(), "repository not found")
}

func TestEnrichSBOM_ErrorHandling(t *testing.T) {
	originalGetRetryClient := getRetryClient

	getRetryClient = func(logger *zerolog.Logger) *http.Client {
		return &http.Client{Transport: httpmock.DefaultTransport}
	}
	defer func() {
		getRetryClient = originalGetRetryClient
	}()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterRegexpResponder("GET", regexp.MustCompile(`https://api\.deps\.dev/.*`),
		httpmock.NewStringResponder(http.StatusNotFound, "Not found"))

	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				Name: "test-package",
				ExternalReferences: &[]cdx.ExternalReference{
					{
						Type: "vcs",
						URL:  "https://github.com/nonexistent/repo",
					},
				},
			},
		},
	}
	doc := &sbom.SBOMDocument{BOM: bom}
	logger := zerolog.Nop()

	EnrichSBOM(doc, &logger)

	component := (*bom.Components)[0]
	assert.Nil(t, component.Properties)
}
