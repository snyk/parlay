package lib

import (
	"context"
	"encoding/json"

	"github.com/snyk/parlay/snyk/users"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
)

const experimentalVersion = "2023-04-28~experimental"

type selfDocument struct {
	Data struct {
		Attributes struct {
			AvatarURL         string `json:"avatar_url,omitempty"`
			DefaultOrgContext string `json:"default_org_context,omitempty"`
			Name              string `json:"name,omitempty"`
			Username          string `json:"username,omitempty"`
		} `json:"attributes,omitempty"`
		ID   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	}
	Jsonapi interface{} `json:"jsonapi,omitempty"`
	Links   interface{} `json:"links,omitempty"`
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

	orgId := userInfo.Data.Attributes.DefaultOrgContext
	org, err := uuid.Parse(orgId)
	if err != nil {
		return nil, err
	}
	return &org, nil
}
