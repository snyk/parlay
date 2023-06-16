package sbom

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	fixedCycloneDX1_4JSON = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	fixedCycloneDX1_4XML  = []byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1"></bom>`)
	fixedSPDX2_2JSON      = []byte(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.2"}`)
)

func TestDecodeSBOMDocument_CycloneDX1_4JSON(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedCycloneDX1_4JSON)
	require.NoError(t, err)

	assert.Equal(t, SBOMFormatCycloneDX1_4JSON, doc.Format)
	assert.NotNil(t, doc.Encode)
	assert.IsType(t, &cyclonedx.BOM{}, doc.BOM)
	assert.Equal(t, cyclonedx.SpecVersion1_4, doc.BOM.SpecVersion)
}

func TestDecodeSBOMDocument_CycloneDX1_4XML(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedCycloneDX1_4XML)
	require.NoError(t, err)

	assert.Equal(t, SBOMFormatCycloneDX1_4XML, doc.Format)
	assert.NotNil(t, doc.Encode)
	assert.IsType(t, &cyclonedx.BOM{}, doc.BOM)
	assert.Equal(t, cyclonedx.SpecVersion1_4, doc.BOM.SpecVersion)
}

func TestDecodeSBOMDocument_Unknown(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedSPDX2_2JSON)

	assert.ErrorContains(t, err, "could not identify SBOM format")
	assert.Nil(t, doc)
}

func Test_identifySBOMFormat(t *testing.T) {
	tc := map[string]struct {
		input  []byte
		format string
		err    string
	}{
		"CycloneDX 1.4 JSON": {
			input:  fixedCycloneDX1_4JSON,
			format: "CycloneDX 1.4 JSON",
			err:    "",
		},
		"CycloneDX 1.4 XML": {
			input:  fixedCycloneDX1_4XML,
			format: "CycloneDX 1.4 XML",
			err:    "",
		},
		"Unknown format": {
			input:  fixedSPDX2_2JSON,
			format: "",
			err:    "could not identify SBOM format",
		},
	}

	for name, tt := range tc {
		t.Run(name, func(t *testing.T) {
			format, err := identifySBOMFormat(tt.input)

			if err != nil {
				assert.ErrorContains(t, err, tt.err)
			}
			assert.Equal(t, tt.format, string(format))
		})
	}
}
