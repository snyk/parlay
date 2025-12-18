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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog"
)

// Project represents a deps.dev project
type Project struct {
	ProjectKey      ProjectKey `json:"projectKey"`
	OpenIssuesCount *int       `json:"openIssuesCount"`
	StarsCount      *int       `json:"starsCount"`
	ForksCount      *int       `json:"forksCount"`
	License         *string    `json:"license"`
	Description     *string    `json:"description"`
	Homepage        *string    `json:"homepage"`
	Scorecard       *Scorecard `json:"scorecard"`
}

type ProjectKey struct {
	ID string `json:"id"`
}

type Scorecard struct {
	OverallScore *float64 `json:"overallScore"`
}

type projectCache struct {
	mu   sync.RWMutex
	data map[string]*Project
}

func newProjectCache() *projectCache {
	return &projectCache{data: make(map[string]*Project)}
}

func (c *projectCache) Get(key string) (*Project, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.data[key]
	return val, ok
}

func (c *projectCache) Set(key string, val *Project) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = val
}

func normalizeRepoURL(repoURL string) string {
	// Handle SSH URLs first
	if strings.HasPrefix(repoURL, "git@") {
		// Convert git@github.com:owner/repo.git to https://github.com/owner/repo
		repoURL = strings.TrimPrefix(repoURL, "git@")
		repoURL = strings.Replace(repoURL, ":", "/", 1)
		repoURL = "https://" + repoURL
	}

	// Remove trailing slashes and .git suffix before parsing
	repoURL = strings.TrimSuffix(repoURL, "/")
	repoURL = strings.TrimSuffix(repoURL, ".git/")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	// Parse the URL
	parsedURL, err := url.Parse(repoURL)
	if err != nil || parsedURL.Host == "" {
		// If parsing fails or no host, return the original URL unchanged
		// This handles cases like "not-a-valid-url/but/has/slashes"
		return repoURL
	}

	// Extract host and path
	host := parsedURL.Host
	path := strings.TrimPrefix(parsedURL.Path, "/")

	// Extract only the first two path segments (owner/repo)
	pathParts := strings.Split(path, "/")
	if len(pathParts) >= 2 {
		path = pathParts[0] + "/" + pathParts[1]
	}

	// Combine host and path
	if path == "" {
		return host
	}
	return host + "/" + path
}

func GetRepoData(repoURL string) (*Project, error) {
	return GetRepoDataWithLogger(repoURL, nil)
}

func GetRepoDataWithLogger(repoURL string, logger *zerolog.Logger) (*Project, error) {
	return GetRepoDataWithCache(repoURL, logger, nil)
}

// getRetryClient is a variable to allow mocking in tests
var getRetryClient = func(logger *zerolog.Logger) *http.Client {
	return createRetryClient(logger)
}

func GetRepoDataWithCache(repoURL string, logger *zerolog.Logger, cache *projectCache) (*Project, error) {
	if logger == nil {
		nop := zerolog.Nop()
		logger = &nop
	}

	normalizedURL := normalizeRepoURL(repoURL)

	if cache != nil {
		if cached, found := cache.Get(normalizedURL); found {
			logger.Debug().Str("repo", normalizedURL).Msg("deps.dev data found in cache")
			return cached, nil
		}
	}

	apiURL := fmt.Sprintf("https://api.deps.dev/v3/projects/%s", url.QueryEscape(normalizedURL))

	client := getRetryClient(logger)
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to deps.dev: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		logger.Debug().Str("repo", normalizedURL).Msg("Repository not found in deps.dev")
		return nil, fmt.Errorf("repository not found in deps.dev")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deps.dev API request failed with status %d", resp.StatusCode)
	}

	var project Project
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("failed to decode deps.dev response: %w", err)
	}

	if cache != nil {
		cache.Set(normalizedURL, &project)
	}
	logger.Debug().Str("repo", normalizedURL).Msg("Successfully fetched deps.dev data")

	return &project, nil
}

func createRetryClient(logger *zerolog.Logger) *http.Client {
	rc := retryablehttp.NewClient()
	rc.RetryMax = 10
	rc.Logger = nil
	rc.ErrorHandler = retryablehttp.PassthroughErrorHandler
	rc.ResponseLogHook = func(_ retryablehttp.Logger, r *http.Response) {
		if r != nil && r.StatusCode >= 400 {
			logger.Warn().Msgf("Unexpected status code (%s) for %s %s", r.Status, r.Request.Method, r.Request.URL.String())
		}
	}
	rc.Backoff = func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		if resp == nil {
			// For transport/client errors, don't add delay so tests and callers fail fast
			return 0
		}

		// Check for Retry-After header for rate limiting
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if sleep, ok := parseRetryAfterHeader(retryAfter); ok {
				logger.Warn().
					Dur("Retry-After", sleep).
					Msg("Getting rate-limited by deps.dev, waiting...")
				return sleep
			}
		}

		return retryablehttp.DefaultBackoff(min, max, attemptNum, resp)
	}

	return rc.StandardClient()
}

func parseRetryAfterHeader(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}

	// First try to parse as seconds
	if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Duration(sec) * time.Second, true
	}

	// Then try to parse as HTTP date
	if t, err := http.ParseTime(v); err == nil {
		sleep := time.Until(t)
		if sleep > 0 {
			return sleep, true
		}
	}

	return 0, false
}
