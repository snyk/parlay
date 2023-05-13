package ecosystems

import (
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestGetRepoData(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(
		"GET",
		"https://repos.ecosyste.ms/api/v1/repositories/lookup",
		httpmock.NewBytesResponder(200, []byte{}),
	)

	_, _ = GetRepoData("https://github.com/golang/go")

	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, calls["GET https://repos.ecosyste.ms/api/v1/repositories/lookup"])
}
