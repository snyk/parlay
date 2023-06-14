package sbom

import (
	"bytes"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func decodeCDX_JSON(b []byte) (*SBOMDocument, error) {
	bom := new(cdx.BOM)

	decoder := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}

	return &SBOMDocument{BOM: bom, encode: encodeCDX_JSON(bom)}, nil
}

func decodeCDX_XML(b []byte) (*SBOMDocument, error) {
	bom := new(cdx.BOM)

	decoder := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatXML)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}

	return &SBOMDocument{BOM: bom, encode: encodeCDX_XML(bom)}, nil
}

func encodeCDX_JSON(bom *cdx.BOM) encodeFn {
	return func(w io.Writer) error {
		return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).Encode(bom)
	}
}

func encodeCDX_XML(bom *cdx.BOM) encodeFn {
	return func(w io.Writer) error {
		return cdx.NewBOMEncoder(w, cdx.BOMFileFormatXML).Encode(bom)
	}
}
