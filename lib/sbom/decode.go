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
