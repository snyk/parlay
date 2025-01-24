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
	"errors"
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"

	"github.com/snyk/parlay/snyk/users"
)

const experimentalVersion = "2023-04-28~experimental"

func SnykOrgID(cfg *Config, auth *securityprovider.SecurityProviderApiKey) (*uuid.UUID, error) {
	experimental, err := users.NewClientWithResponses(
		cfg.SnykAPIURL+"/rest",
		users.WithRequestEditorFn(auth.Intercept))
	if err != nil {
		return nil, err
	}

	userParams := users.GetSelfParams{Version: experimentalVersion}
	self, err := experimental.GetSelfWithResponse(context.Background(), &userParams)
	if err != nil {
		return nil, err
	}

	if self.HTTPResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user info (%s).", self.HTTPResponse.Status)
	}

	user, err := self.ApplicationvndApiJSON200.Data.Attributes.AsUser20240422()
	if err != nil {
		return nil, err
	}

	if org := user.DefaultOrgContext; org != nil {
		return org, nil
	}

	return nil, errors.New("Failed to get org ID.")
}

func AuthFromToken(token string) (*securityprovider.SecurityProviderApiKey, error) {
	if token == "" {
		return nil, errors.New("Must provide a SNYK_TOKEN environment variable")
	}

	auth, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", fmt.Sprintf("token %s", token))
	if err != nil {
		return nil, err
	}

	return auth, nil
}
