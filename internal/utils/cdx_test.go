package utils_test

import (
	"testing"

	"github.com/snyk/parlay/internal/utils"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestDiscoverCDXComponents(t *testing.T) {
	assert := assert.New(t)

	bom := &cdx.BOM{
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				Name: "MetaComp",
			},
		},
		Components: &[]cdx.Component{
			{
				Name: "Parent",
				Components: &[]cdx.Component{
					{Name: "Child"},
				},
			},
		},
	}
	result := utils.DiscoverCDXComponents(bom)

	assert.Equal(len(result), 3)
}
