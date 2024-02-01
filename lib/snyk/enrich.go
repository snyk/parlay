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

package snyk

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/rs/zerolog"
	"github.com/spdx/tools-golang/spdx"

	"github.com/snyk/parlay/lib/sbom"
)

func EnrichSBOM(doc *sbom.SBOMDocument, logger zerolog.Logger) *sbom.SBOMDocument {
	switch bom := doc.BOM.(type) {
	case *cdx.BOM:
		enrichCycloneDX(bom, logger)
	case *spdx.Document:
		enrichSPDX(bom, logger)
	}

	return doc
}
