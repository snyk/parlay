package snyk

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/snyk/parlay/snyk/issues"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/package-url/packageurl-go"
)

const snykServer = "https://api.snyk.io/rest"
const version = "2023-04-28"

func GetPackageVulnerabilities(purl packageurl.PackageURL) (*issues.FetchIssuesPerPurlResponse, error) {
	token := os.Getenv("SNYK_TOKEN")
	if token == "" {
		return nil, errors.New("Must provide a SNYK_TOKEN environment variable")
	}

	auth, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", fmt.Sprintf("token %s", token))
	if err != nil {
		return nil, err
	}

	org, err := getSnykOrg(auth)
	if err != nil {
		return nil, err
	}

	client, err := issues.NewClientWithResponses(snykServer, issues.WithRequestEditorFn(auth.Intercept))
	if err != nil {
		return nil, err
	}

	params := issues.FetchIssuesPerPurlParams{Version: version}
	resp, err := client.FetchIssuesPerPurlWithResponse(context.Background(), *org, purl.ToString(), &params)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
