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
	"encoding/json"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"

	"github.com/snyk/parlay/snyk/users"
)

const experimentalVersion = "2023-04-28~experimental"

type selfDocument struct {
	Data struct {
		Attributes users.User `json:"attributes,omitempty"`
	}
}

func getSnykOrg(auth *securityprovider.SecurityProviderApiKey) (*uuid.UUID, error) {
	experimental, err := users.NewClientWithResponses(snykServer, users.WithRequestEditorFn(auth.Intercept))
	if err != nil {
		return nil, err
	}

	userParams := users.GetSelfParams{Version: experimentalVersion}
	self, err := experimental.GetSelfWithResponse(context.Background(), &userParams)
	if err != nil {
		return nil, err
	}

	var userInfo selfDocument
	if err = json.Unmarshal(self.Body, &userInfo); err != nil {
		return nil, err
	}

	org := userInfo.Data.Attributes.DefaultOrgContext

	return org, nil
}
