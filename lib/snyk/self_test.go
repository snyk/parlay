package snyk

import (
	"net/http"
	"testing"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestGetSnykOrg(t *testing.T) {
	expectedOrg := uuid.New()
	auth, _ := securityprovider.NewSecurityProviderApiKey("header", "name", "value")

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("GET", "https://api.snyk.io/rest/self",
		func(req *http.Request) (*http.Response, error) {
			jsonBody := `{
				"data": {
					"attributes": {
						"default_org_context": "` + expectedOrg.String() + `"
					}
				}
			}`
			resp := httpmock.NewStringResponse(200, jsonBody)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)

	actualOrg, err := getSnykOrg(auth)
	assert.NoError(t, err)
	assert.Equal(t, expectedOrg, *actualOrg)
}
