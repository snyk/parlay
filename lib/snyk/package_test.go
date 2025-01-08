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

package snyk

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPackageVulnerabilities_RetryRateLimited(t *testing.T) {
	logger := zerolog.Nop()
	var numRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		numRequests++
		if numRequests == 1 {
			w.Header().Set("X-RateLimit-Reset", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.json+api")
		_, err := w.Write([]byte(`{"data":[{"type":"issues","id":"VULN-ID"}]}`))
		require.NoError(t, err)
	}))
	cfg := DefaultConfig()
	cfg.SnykAPIURL = srv.URL

	auth, err := AuthFromToken("asdf")
	require.NoError(t, err)

	purl, err := packageurl.FromString("pkg:golang/github.com/snyk/parlay")
	require.NoError(t, err)

	orgID := uuid.New()
	issues, err := GetPackageVulnerabilities(cfg, &purl, auth, &orgID, &logger)
	require.NoError(t, err)

	assert.Equal(t, 2, numRequests, "retries failed requests")
	assert.NotNil(t, issues, "should retrieve issues")
}

func TestGetPackageVulnerabilities_HandlesNilResponses(t *testing.T) {
	logger := zerolog.Nop()
	var numRequests int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		numRequests++
		if numRequests < 5 {
			w.Header().Set("X-RateLimit-Reset", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// Induce a client error which results in a nil response
		srv.CloseClientConnections()
	}))

	cfg := DefaultConfig()
	cfg.SnykAPIURL = srv.URL

	auth, err := AuthFromToken("asdf")
	require.NoError(t, err)

	purl, err := packageurl.FromString("pkg:golang/github.com/snyk/parlay")
	require.NoError(t, err)

	orgID := uuid.New()
	issues, err := GetPackageVulnerabilities(cfg, &purl, auth, &orgID, &logger)

	require.Error(t, err)
	assert.Nil(t, issues)
}
