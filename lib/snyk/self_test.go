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
	_ "embed"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/self.json
var selfBody []byte

func TestSnykOrgID_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond(w, selfBody)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.SnykAPIURL = srv.URL
	auth, err := securityprovider.NewSecurityProviderApiKey("header", "authorization", "asdf")
	require.NoError(t, err)

	actualOrg, err := SnykOrgID(cfg, auth)

	assert.NoError(t, err)
	assert.Equal(t, uuid.MustParse("00000000-0000-0000-0000-000000000000"), *actualOrg)
}

func TestSnykOrgID_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		respond(w, []byte(`{"msg":"unauthorized"}`))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.SnykAPIURL = srv.URL
	auth, err := securityprovider.NewSecurityProviderApiKey("header", "authorization", "asdf")
	require.NoError(t, err)

	actualOrg, err := SnykOrgID(cfg, auth)

	assert.ErrorContains(t, err, "Failed to get user info (401 Unauthorized)")
	assert.Nil(t, actualOrg)
}
