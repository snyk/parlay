package utils

import (
	"bytes"
	"errors"
	"io"

	"github.com/snyk/parlay/internal/flags"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type encoder func(io.Writer) error

type SBOMDocument struct {
	BOM interface{}

	encode encoder
}

func (doc *SBOMDocument) Encode(writer io.Writer) error {
	return doc.encode(writer)
}

func UnmarshalSBOM(b []byte, f *flags.SBOMFormat) (*SBOMDocument, error) {
	switch *f {
	case flags.SBOMFormatCycloneDX1_4JSON:
		return decodeCDX_JSON(b)
	case flags.SBOMFormatCycloneDX1_4XML:
		return decodeCDX_XML(b)
	default:
		return nil, errors.New("unsupported format given")
	}
}

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

func encodeCDX_JSON(bom *cdx.BOM) encoder {
	return func(w io.Writer) error {
		return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).Encode(bom)
	}
}

func encodeCDX_XML(bom *cdx.BOM) encoder {
	return func(w io.Writer) error {
		return cdx.NewBOMEncoder(w, cdx.BOMFileFormatXML).Encode(bom)
	}
}
