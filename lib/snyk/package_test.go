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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPackageVulnerabilities_RetryRateLimited(t *testing.T) {
	retryMax = 2
	t.Cleanup(func() { retryMax = 20 })
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
	retryMax = 2
	t.Cleanup(func() { retryMax = 20 })
	logger := zerolog.Nop()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestRateLimiterWait_BlocksDuringBackoff(t *testing.T) {
	rl := newRateLimiter()
	rl.backoff(100 * time.Millisecond)

	start := time.Now()
	err := rl.wait(context.Background())
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 80*time.Millisecond, "wait should block for ~backoff duration")
}

func TestRateLimiterWait_ClearsBackoffAfterExpiry(t *testing.T) {
	rl := newRateLimiter()
	rl.backoff(10 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	err := rl.wait(context.Background())
	require.NoError(t, err)

	rl.mu.Lock()
	assert.True(t, rl.backoffUntil.IsZero(), "backoffUntil should be cleared after expiry")
	rl.mu.Unlock()
}

func TestRateLimiterWait_RespectsContextCancellation(t *testing.T) {
	rl := newRateLimiter()
	rl.backoff(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := rl.wait(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestParseRateLimitResetHeader(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantOk       bool
		wantDuration time.Duration
	}{
		{
			name:         "seconds",
			input:        "60",
			wantOk:       true,
			wantDuration: 60 * time.Second,
		},
		{
			name:         "empty",
			input:        "",
			wantOk:       false,
			wantDuration: 0,
		},
		{
			name:         "zero",
			input:        "0",
			wantOk:       false,
			wantDuration: 0,
		},
		{
			name:         "negative",
			input:        "-1",
			wantOk:       false,
			wantDuration: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sleep, ok := parseRateLimitResetHeader(tc.input)

			assert.Equal(t, tc.wantOk, ok)
			assert.Equal(t, tc.wantDuration, sleep)
		})
	}
}
