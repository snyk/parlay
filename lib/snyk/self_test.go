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
	"testing"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSnykOrg_Success(t *testing.T) {
	expectedOrg := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	auth, err := securityprovider.NewSecurityProviderApiKey("header", "name", "value")
	require.NoError(t, err)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("GET", "https://api.snyk.io/rest/self",
		httpmock.NewJsonResponderOrPanic(http.StatusOK, httpmock.File("testdata/self.json")),
	)

	actualOrg, err := SnykOrgID(auth)
	assert.NoError(t, err)
	assert.Equal(t, expectedOrg, *actualOrg)
}

func TestGetSnykOrg_Unauthorized(t *testing.T) {
	auth, err := securityprovider.NewSecurityProviderApiKey("header", "name", "value")
	require.NoError(t, err)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("GET", "https://api.snyk.io/rest/self",
		httpmock.NewJsonResponderOrPanic(http.StatusUnauthorized, []byte(`{"msg":"unauthorized"}`)),
	)

	actualOrg, err := SnykOrgID(auth)
	assert.ErrorContains(t, err, "Failed to get user info (401)")
	assert.Nil(t, actualOrg)
}
