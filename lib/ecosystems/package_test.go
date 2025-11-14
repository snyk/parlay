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
	"net/http"
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

func TestGetPackageDataUserAgent(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	var capturedUserAgent string
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			capturedUserAgent = req.Header.Get("User-Agent")
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)

	purl, err := packageurl.FromString("pkg:npm/lodash@4.17.21")
	require.NoError(t, err)

	_, err = GetPackageData(purl)
	require.NoError(t, err)

	expectedUserAgent := fmt.Sprintf("parlay (%s)", Version)
	assert.Equal(t, expectedUserAgent, capturedUserAgent)
	// Verify it contains "parlay" and the version in parentheses
	assert.Contains(t, capturedUserAgent, "parlay")
	assert.Contains(t, capturedUserAgent, "(")
	assert.Contains(t, capturedUserAgent, ")")
}

func TestGetPackageVersionDataUserAgent(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	var capturedUserAgent string
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		func(req *http.Request) (*http.Response, error) {
			capturedUserAgent = req.Header.Get("User-Agent")
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)

	purl, err := packageurl.FromString("pkg:npm/lodash@4.17.21")
	require.NoError(t, err)

	_, err = GetPackageVersionData(purl)
	require.NoError(t, err)

	assert.Equal(t, fmt.Sprintf("parlay (%s)", Version), capturedUserAgent)
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
		{"pkg:cocoapods/Firebase@7.0.0", "cocoapods.org"},
		{"pkg:apk/alpine/curl@7.79.1-r0", "alpine-edge"},
		{"pkg:swift/github.com/yonaskolb/XcodeGen@2.34.0", "swiftpackageindex.com"},
		{"pkg:docker/library%2Falpine", "hub.docker.com"},
		{"pkg:bower/jquery@3.6.0", "bower.io"},
		{"pkg:brew/wget@1.21.3", "formulae.brew.sh"},
		{"pkg:carthage/Alamofire/Alamofire@5.6.4", "carthage"},
		{"pkg:clojars/ring/ring-core@1.9.5", "clojars.org"},
		{"pkg:conda/numpy@1.23.5", "anaconda.org"},
		{"pkg:cpan/DBI@1.643", "metacpan.org"},
		{"pkg:cran/ggplot2@3.4.0", "cran.r-project.org"},
		{"pkg:elm/elm/core@1.0.5", "package.elm-lang.org"},
		{"pkg:hackage/aeson@2.1.0.0", "hackage.haskell.org"},
		{"pkg:julia/Example@0.5.3", "juliahub.com"},
		{"pkg:pub/http@0.13.5", "pub.dev"},
		{"pkg:puppet/puppetlabs/stdlib@8.5.0", "forge.puppet.com"},
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
			purlStr:      "pkg:npm/%40my-namespace/my-package",
			expectedName: "@my-namespace/my-package",
		},
		{
			// Test case 2: When the package manager type is "npm"
			// and the namespace is empty, the function should return
			// the package name as is.
			purlStr:      "pkg:npm/my-package",
			expectedName: "my-package",
		},
		{
			// Test case 3: When the package manager type is "maven"
			// and the namespace is not empty, the function should return
			// a string in the form of "<namespace>:<name>"
			purlStr:      "pkg:maven/my-group:my-artifact",
			expectedName: "my-group:my-artifact",
		},
		{
			// Test case 4: When the package manager type is "maven"
			// and the namespace is empty, the function should return
			// the package name as is.
			purlStr:      "pkg:maven/my-artifact",
			expectedName: "my-artifact",
		},
		{
			// Test case 5: When the package manager type is "golang"
			// and the namespace is not empty, the function should return
			// a string in the form of "<namespace>/<name>"
			purlStr:      "pkg:golang/example.com/foo/bar@v1.5.0",
			expectedName: "example.com/foo/bar",
		},
		{
			// Test case 6: When the package manager type is "golang"
			// and the namespace has lots of weird characters, make sure
			// they get filtered properly
			purlStr:      "pkg:golang/example.com/f.o_o/ba~r",
			expectedName: "example.com/f.o_o/ba~r",
		},
		{
			// Test case 7: When the package manager type is "swift"
			purlStr:      "pkg:swift/github.com/yonaskolb/XcodeGen@1",
			expectedName: "github.com/yonaskolb/XcodeGen",
		},
		{
			// Test case 8: When the package manager type is "apk"
			purlStr:      "pkg:apk/alpine/lf@30-r3",
			expectedName: "lf",
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
