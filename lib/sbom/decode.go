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
	"errors"
	"fmt"
)

func DecodeSBOMDocument(b []byte) (*SBOMDocument, error) {
	doc := new(SBOMDocument)

	format, err := identifySBOMFormat(b)
	if err != nil {
		return nil, err
	}
	doc.Format = format

	switch doc.Format {
	case SBOMFormatCycloneDX1_4JSON:
		bom, err := decodeCycloneDX1_4JSON(b)
		if err != nil {
			return nil, fmt.Errorf("could not decode input: %w", err)
		}
		doc.BOM = bom
		doc.encode = encodeCycloneDX1_4JSON(doc.BOM)
	case SBOMFormatCycloneDX1_4XML:
		bom, err := decodeCycloneDX1_4XML(b)
		if err != nil {
			return nil, fmt.Errorf("could not decode input: %w", err)
		}
		doc.BOM = bom
		doc.encode = encodeCycloneDX1_4XML(doc.BOM)
	default:
		return nil, fmt.Errorf("no decoder for format %s", doc.Format)
	}

	return doc, nil
}

func identifySBOMFormat(b []byte) (SBOMFormat, error) {
	if bytes.Contains(b, []byte("bomFormat")) && bytes.Contains(b, []byte("CycloneDX")) {
		return SBOMFormatCycloneDX1_4JSON, nil
	}

	if bytes.Contains(b, []byte("xmlns")) && bytes.Contains(b, []byte("cyclonedx")) {
		return SBOMFormatCycloneDX1_4XML, nil
	}

	return "", errors.New("could not identify SBOM format")
}
