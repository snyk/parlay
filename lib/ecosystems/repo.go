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
	"context"

	"github.com/snyk/parlay/ecosystems/repos"
)

const repos_server = "https://repos.ecosyste.ms/api/v1"

func GetRepoData(url string) (*repos.RepositoriesLookupResponse, error) {
	client, err := repos.NewClientWithResponses(repos_server)
	if err != nil {
		return nil, err
	}
	params := repos.RepositoriesLookupParams{Url: &url}
	resp, err := client.RepositoriesLookupWithResponse(context.Background(), &params)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
