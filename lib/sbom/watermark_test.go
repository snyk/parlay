/*
 * © 2024 Snyk Limited All rights reserved.
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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddParlayWatermark_CycloneDX(t *testing.T) {
	doc, err := DecodeSBOMDocument([]byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6"
	}`))
	require.NoError(t, err)

	AddParlayWatermark(doc, "0.0.0")

	bom, ok := doc.BOM.(*cdx.BOM)
	require.True(t, ok)

	require.NotNil(t, bom.Metadata.Tools.Components)
	require.Len(t, *bom.Metadata.Tools.Components, 1)
	tool := (*bom.Metadata.Tools.Components)[0]
	assert.Equal(t, "application", string(tool.Type))
	assert.Equal(t, "parlay", tool.Name)
	assert.Equal(t, "0.0.0", tool.Version)
	assert.Equal(t, "Snyk", tool.Publisher)
}

func TestAddParlayWatermark_SPDX(t *testing.T) {
	doc, err := DecodeSBOMDocument([]byte(`{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT"
	}`))
	require.NoError(t, err)

	AddParlayWatermark(doc, "0.0.0")

	bom, ok := doc.BOM.(*spdx.Document)
	require.True(t, ok)

	assert.Contains(t, bom.CreationInfo.Creators, spdx.Creator{Creator: "parlay", CreatorType: "Tool"})
}
