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
	params := repos.RepositoriesLookupParams{Url: url}
	resp, err := client.RepositoriesLookupWithResponse(context.Background(), &params)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
