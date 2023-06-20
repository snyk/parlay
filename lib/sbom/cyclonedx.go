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
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func decodeCycloneDX1_4JSON(b []byte) (*cdx.BOM, error) {
	return decodeCycloneDX(b, cdx.BOMFileFormatJSON)
}

func decodeCycloneDX1_4XML(b []byte) (*cdx.BOM, error) {
	return decodeCycloneDX(b, cdx.BOMFileFormatXML)
}

func decodeCycloneDX(b []byte, f cdx.BOMFileFormat) (*cdx.BOM, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(b), f)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}

func encodeCycloneDX1_4JSON(bom *cdx.BOM) encoderFn {
	return encodeCycloneDX(bom, cdx.BOMFileFormatJSON)
}

func encodeCycloneDX1_4XML(bom *cdx.BOM) encoderFn {
	return encodeCycloneDX(bom, cdx.BOMFileFormatXML)
}

func encodeCycloneDX(bom *cdx.BOM, f cdx.BOMFileFormat) encoderFn {
	return func(w io.Writer) error {
		return cdx.NewBOMEncoder(w, f).Encode(bom)
	}
}
