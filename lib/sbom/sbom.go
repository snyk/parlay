package sbom

import (
	"errors"
	"io"
)

type encodeFn func(io.Writer) error

type encoder interface {
	Encode(io.Writer) error
}

type SBOMDocument struct {
	BOM    interface{}
	encode encodeFn
}

func (doc *SBOMDocument) Encode(writer io.Writer) error {
	return doc.encode(writer)
}

var _ encoder = (*SBOMDocument)(nil)

func UnmarshalSBOM(b []byte, f *SBOMFormat) (*SBOMDocument, error) {
	switch *f {
	case SBOMFormatCycloneDX1_4JSON:
		return decodeCDX_JSON(b)
	case SBOMFormatCycloneDX1_4XML:
		return decodeCDX_XML(b)
	case SBOMFormatSPDX2_3JSON:
		return decodeSPDX2_3JSON(b)
	default:
		return nil, errors.New("unsupported format given")
	}
}
