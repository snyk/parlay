package snyk

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
		Attributes users.User `json:"attributes,omitempty"`
		ID         string     `json:"id,omitempty"`
		Type       string     `json:"type,omitempty"`
	}
	Jsonapi users.JsonApi `json:"jsonapi,omitempty"`
	Links   users.Links   `json:"links,omitempty"`
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
