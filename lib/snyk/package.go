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

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"

	"github.com/snyk/parlay/snyk/issues"
)

const snykServer = "https://api.snyk.io/rest"
const version = "2023-04-28"

func GetPackageVulnerabilities(purl *packageurl.PackageURL, auth *securityprovider.SecurityProviderApiKey, orgID *uuid.UUID) (*issues.FetchIssuesPerPurlResponse, error) {
	client, err := issues.NewClientWithResponses(snykServer, issues.WithRequestEditorFn(auth.Intercept))
	if err != nil {
		return nil, err
	}

	params := issues.FetchIssuesPerPurlParams{Version: version}
	resp, err := client.FetchIssuesPerPurlWithResponse(context.Background(), *orgID, purl.ToString(), &params)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
