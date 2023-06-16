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
