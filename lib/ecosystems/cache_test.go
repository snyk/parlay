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
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryCache_GetPackageData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockResponse := `{"name": "test-package", "description": "Test package"}`
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, mockResponse),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	resp1, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp1)

	resp2, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp2)
	assert.Equal(t, resp1, resp2)

	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 1, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_GetPackageVersionData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockResponse := `{"number": "1.0.0", "licenses": "MIT"}`
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, mockResponse),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	resp1, err := cache.GetPackageVersionData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp1)

	resp2, err := cache.GetPackageVersionData(purl)
	assert.NoError(t, err)
	assert.NotNil(t, resp2)
	assert.Equal(t, resp1, resp2)

	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 0, pkgCacheSize)
	assert.Equal(t, 1, versionCacheSize)
}

func TestInMemoryCache_DifferentPackages(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, `{}`),
	)

	cache := NewInMemoryCache()
	purl1, err := packageurl.FromString("pkg:npm/package1@1.0.0")
	require.NoError(t, err)
	purl2, err := packageurl.FromString("pkg:npm/package2@1.0.0")
	require.NoError(t, err)

	_, err = cache.GetPackageData(purl1)
	assert.NoError(t, err)
	_, err = cache.GetPackageData(purl2)
	assert.NoError(t, err)

	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 2, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 2, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_SamePackageDifferentVersions(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, `{}`),
	)

	cache := NewInMemoryCache()
	purl1, err := packageurl.FromString("pkg:npm/package@1.0.0")
	require.NoError(t, err)
	purl2, err := packageurl.FromString("pkg:npm/package@2.0.0")
	require.NoError(t, err)

	_, err = cache.GetPackageData(purl1)
	assert.NoError(t, err)
	_, err = cache.GetPackageData(purl2)
	assert.NoError(t, err)

	// Different versions = different cache entries
	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 2, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 2, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_APIError(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// HTTP client returns a successful response even with 500 status
	// So we need to test that the client properly handles this case
	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(500, `{"error": "internal server error"}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	// HTTP client doesn't treat 500 as error
	resp1, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 500, resp1.StatusCode())

	resp2, err := cache.GetPackageData(purl)
	assert.NoError(t, err)
	assert.Equal(t, 500, resp2.StatusCode())
	assert.Equal(t, resp1, resp2)

	// Second call used cache
	callCount := httpmock.GetTotalCallCount()
	assert.Equal(t, 1, callCount)

	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 1, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)
}

func TestInMemoryCache_ConcurrentAccess(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		`=~^https://packages.ecosyste.ms/api/v1/registries`,
		httpmock.NewStringResponder(200, `{}`),
	)

	cache := NewInMemoryCache()
	purl, err := packageurl.FromString("pkg:npm/test-package@1.0.0")
	require.NoError(t, err)

	done := make(chan bool)
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_, err := cache.GetPackageData(purl)
			assert.NoError(t, err)
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Should only have one entry despite concurrent access
	pkgCacheSize, versionCacheSize := cache.GetCacheStats()
	assert.Equal(t, 1, pkgCacheSize)
	assert.Equal(t, 0, versionCacheSize)

	// API should have been called at least once, but maybe more due to race conditions
	// can't guarantee exactly 1 call due to concurrent access, but it should at least less than 10
	callCount := httpmock.GetTotalCallCount()
	assert.True(t, callCount >= 1 && callCount <= numGoroutines)
}
