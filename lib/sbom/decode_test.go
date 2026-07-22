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

package sbom

import (
	"bytes"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
	spdx_2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	fixedCycloneDX1_4JSON = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	fixedCycloneDX1_4XML  = []byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1"></bom>`)
	fixedCycloneDX1_7JSON = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"citations":[{"note":"source"}]}`)
	fixedCycloneDX1_7XML  = []byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.7" version="1"><citations><citation><note>source</note></citation></citations></bom>`)
	fixedSPDX2_3JSON      = []byte(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3"}`)
	fixedSPDX2_2JSON      = []byte(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.2"}`)
)

func TestDecodeSBOMDocument_CycloneDX1_4JSON(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedCycloneDX1_4JSON)
	require.NoError(t, err)

	bom, ok := doc.BOM.(*cyclonedx.BOM)
	require.True(t, ok)

	assert.Equal(t, SBOMFormatCycloneDX1_4JSON, doc.Format)
	assert.NotNil(t, doc.Encode)
	assert.Equal(t, cyclonedx.SpecVersion1_4, bom.SpecVersion)
}

func TestDecodeSBOMDocument_CycloneDX1_4XML(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedCycloneDX1_4XML)
	require.NoError(t, err)

	bom, ok := doc.BOM.(*cyclonedx.BOM)
	require.True(t, ok)

	assert.Equal(t, SBOMFormatCycloneDX1_4XML, doc.Format)
	assert.NotNil(t, doc.Encode)
	assert.Equal(t, cyclonedx.SpecVersion1_4, bom.SpecVersion)
}

func TestDecodeSBOMDocument_CycloneDX1_7JSON(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedCycloneDX1_7JSON)
	require.NoError(t, err)

	bom, ok := doc.BOM.(*cyclonedx.BOM)
	require.True(t, ok)

	assert.Equal(t, cyclonedx.SpecVersion1_7, bom.SpecVersion)
	require.NotNil(t, bom.Citations)
	require.Len(t, *bom.Citations, 1)
	assert.Equal(t, "source", (*bom.Citations)[0].Note)

	var output bytes.Buffer
	require.NoError(t, doc.Encode(&output))
	assert.Contains(t, output.String(), `"specVersion":"1.7"`)
	assert.Contains(t, output.String(), `"citations":[{"note":"source"}]`)
}

func TestDecodeSBOMDocument_CycloneDX1_7XML(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedCycloneDX1_7XML)
	require.NoError(t, err)

	bom, ok := doc.BOM.(*cyclonedx.BOM)
	require.True(t, ok)

	assert.Equal(t, cyclonedx.SpecVersion1_7, bom.SpecVersion)
	require.NotNil(t, bom.Citations)
	require.Len(t, *bom.Citations, 1)
	assert.Equal(t, "source", (*bom.Citations)[0].Note)

	var output bytes.Buffer
	require.NoError(t, doc.Encode(&output))
	assert.Contains(t, output.String(), `xmlns="http://cyclonedx.org/schema/bom/1.7"`)
	assert.Contains(t, output.String(), `<citations><citation><note>source</note></citation></citations>`)
}

func TestDecodeSBOMDocument_SPDX2_3JSON(t *testing.T) {
	doc, err := DecodeSBOMDocument(fixedSPDX2_3JSON)
	require.NoError(t, err)

	bom, ok := doc.BOM.(*spdx.Document)
	require.True(t, ok)

	assert.Equal(t, SBOMFormatSPDX2_3JSON, doc.Format)
	assert.NotNil(t, doc.Encode)
	assert.Equal(t, spdx_2_3.Version, bom.SPDXVersion)
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
