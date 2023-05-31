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
)

// Project represents a deps.dev project with proper field types
type Project struct {
	ProjectKey      ProjectKey `json:"projectKey"`
	OpenIssuesCount int        `json:"openIssuesCount"`
	StarsCount      int        `json:"starsCount"`
	Scorecard       Scorecard  `json:"scorecard"`
}

type ProjectKey struct {
	ID string `json:"id"`
}

type Scorecard struct {
	OverallScore float64 `json:"overallScore"`
}

func GetRepoData(repoURL string) (*Project, error) {
	// Build the API URL
	apiURL := fmt.Sprintf("https://api.deps.dev/v3alpha/projects/%s", url.QueryEscape(repoURL))

	// Make the HTTP request
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	// Parse the response
	var project Project
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &project, nil
}
