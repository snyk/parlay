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

package ecosystems

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPackageData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewBytesResponder(200, []byte{}),
	)

	purl, err := packageurl.FromString("pkg:maven/org.springframework.boot/spring-boot-starter-jdb")
	require.NoError(t, err)

	_, err = GetPackageData(purl)
	require.NoError(t, err)

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, calls[`GET =~^https://packages.ecosyste.ms/api/v1/registries`])
}

func TestPurlToEcosystemsRegistry(t *testing.T) {
	testCases := []struct {
		purlStr  string
		expected string
	}{
		{"pkg:npm/lodash@4.17.21", "npmjs.org"},
		{"pkg:golang/github.com/golang/example/hello?go-get=1", "proxy.golang.org"},
		{"pkg:nuget/Microsoft.AspNetCore.Http.Abstractions@2.2.0", "nuget.org"},
		{"pkg:hex/plug@1.11.0", "hex.pm"},
		{"pkg:maven/com.google.guava/guava@28.2-jre", "repo1.maven.org"},
		{"pkg:pypi/Django@2.2.7", "pypi.org"},
		{"pkg:composer/symfony/http-foundation@5.3.0", "packagist.org"},
		{"pkg:gem/rspec-core@3.10.1", "rubygems.org"},
		{"pkg:cargo/rand@0.8.4", "crates.io"},
		{"pkg:cocoapods/Firebase@7.0.0", "cocoapod.org"},
		{"pkg:apk/curl@7.79.1-r0", "alpine"},
	}

	for _, tc := range testCases {
		purl, err := packageurl.FromString(tc.purlStr)
		if err != nil {
			t.Errorf("Error creating PackageURL: %v", err)
		}
		got := purlToEcosystemsRegistry(purl)
		if got != tc.expected {
			t.Errorf("purlToEcosystemsRegistry(%q) = %q; expected %q", tc.purlStr, got, tc.expected)
		}
	}
}

func TestPurlToEcosystemsName(t *testing.T) {
	testCases := []struct {
		purlStr      string
		expectedName string
	}{
		{
			// Test case 1: When the package manager type is "npm"
			// and the namespace is not empty, the function should return
			// a url encoded string in the form of "<namespace>/<name>"
			purlStr:      "pkg:npm/my-namespace/my-package",
			expectedName: url.QueryEscape("my-namespace/my-package"),
		},
		{
			// Test case 2: When the package manager type is "npm"
			// and the namespace is empty, the function should return
			// the package name as is.
			purlStr:      "pkg:npm/my-package",
			expectedName: "my-package",
		},
		{
			// Test case 3: When the package manager type is not "npm"
			// and the namespace is not empty, the function should return
			// a string in the form of "<namespace>:<name>"
			purlStr:      "pkg:maven/my-group:my-artifact",
			expectedName: "my-group:my-artifact",
		},
		{
			// Test case 4: When the package manager type is not "npm"
			// and the namespace is empty, the function should return
			// the package name as is.
			purlStr:      "pkg:maven/my-artifact",
			expectedName: "my-artifact",
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Test %v", testCase.purlStr), func(t *testing.T) {
			purl, err := packageurl.FromString(testCase.purlStr)
			if err != nil {
				t.Fatalf("Failed to create PackageURL: %v", err)
			}

			result := purlToEcosystemsName(purl)
			if result != testCase.expectedName {
				t.Errorf("Expected %q, but got %q", testCase.expectedName, result)
			}
		})
	}
}
