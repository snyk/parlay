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
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"

	"github.com/snyk/parlay/snyk/issues"
)

const version = "2023-04-28"

func purlToSnykAdvisor(purl *packageurl.PackageURL) string {
	return map[string]string{
		packageurl.TypeNPM:    "npm-package",
		packageurl.TypePyPi:   "python",
		packageurl.TypeGolang: "golang",
		packageurl.TypeDocker: "docker",
	}[purl.Type]
}

func SnykAdvisorURL(cfg *Config, purl *packageurl.PackageURL) string {
	ecosystem := purlToSnykAdvisor(purl)
	if ecosystem == "" {
		return ""
	}
	url := snykAdvisorWebURL + "/" + ecosystem + "/"
	if purl.Namespace != "" {
		url += purl.Namespace + "/"
	}
	url += purl.Name
	return url
}

func purlToSnykVulnDB(purl *packageurl.PackageURL) string {
	return map[string]string{
		packageurl.TypeCargo:     "cargo",
		packageurl.TypeCocoapods: "cocoapods",
		packageurl.TypeComposer:  "composer",
		packageurl.TypeGolang:    "golang",
		packageurl.TypeHex:       "hex",
		packageurl.TypeMaven:     "maven",
		packageurl.TypeNPM:       "npm",
		packageurl.TypeNuget:     "nuget",
		packageurl.TypePyPi:      "pip",
		packageurl.TypePub:       "pub",
		packageurl.TypeGem:       "rubygems",
		packageurl.TypeSwift:     "swift",
	}[purl.Type]
}

func SnykVulnURL(cfg *Config, purl *packageurl.PackageURL) string {
	ecosystem := purlToSnykVulnDB(purl)
	if ecosystem == "" {
		return ""
	}
	url := snykVulnerabilityDBWebURL + "/package/" + ecosystem + "/"
	if purl.Namespace != "" {
		url += purl.Namespace + "%2F"
	}
	url += purl.Name
	return url
}

func GetPackageVulnerabilities(cfg *Config, purl *packageurl.PackageURL, auth *securityprovider.SecurityProviderApiKey, orgID *uuid.UUID, logger *zerolog.Logger) (*issues.FetchIssuesPerPurlResponse, error) {
	client, err := issues.NewClientWithResponses(
		cfg.SnykAPIURL,
		issues.WithRequestEditorFn(auth.Intercept),
		issues.WithHTTPClient(getRetryClient(logger)))
	if err != nil {
		return nil, err
	}

	params := issues.FetchIssuesPerPurlParams{Version: version}
	resp, err := client.FetchIssuesPerPurlWithResponse(context.Background(), *orgID, purl.ToString(), &params)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return resp, fmt.Errorf("unsuccessful request (%s)", resp.Status())
	}

	return resp, nil
}

func getRetryClient(logger *zerolog.Logger) *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil
	rc.Backoff = func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		if sleep, ok := parseRateLimitHeader(resp.Header.Get("X-RateLimit-Reset")); ok {
			logger.Warn().
				Dur("Retry-After", sleep).
				Msg("Getting rate-limited, waiting...")
			return sleep
		}
		return retryablehttp.DefaultBackoff(min, max, attemptNum, resp)
	}

	return rc.StandardClient()
}

func parseRateLimitHeader(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}

	if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Duration(sec) * time.Second, true
	}

	return 0, false
}
