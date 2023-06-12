package utils

import (
	"bytes"
	"errors"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type (
	parser     func([]byte) interface{}
	serializer func(interface{}, io.Writer) error
)

// IdentifySBOM receives an unknown byte array and attempts to
// match it to a known SBOM format. It returns a corresponding
// serializer function to convert the SBOM back into bytes.
func IdentifySBOM(b []byte) (interface{}, serializer) {
	var bom interface{}
	var serialize serializer

	for _, format := range []struct {
		parse     parser
		serialize serializer
	}{
		{parseCycloneDX_JSON, serializeCycloneDX_JSON},
		{parseCycloneDX_XML, serializeCycloneDX_XML},
	} {
		bom = format.parse(b)
		if bom != nil {
			serialize = format.serialize
			break
		}
	}

	return bom, serialize
}

var (
	parseCycloneDX_JSON     parser     = parseCycloneDX(cdx.BOMFileFormatJSON)
	parseCycloneDX_XML      parser     = parseCycloneDX(cdx.BOMFileFormatXML)
	serializeCycloneDX_JSON serializer = serializeCycloneDX(cdx.BOMFileFormatJSON)
	serializeCycloneDX_XML  serializer = serializeCycloneDX(cdx.BOMFileFormatXML)
)

func parseCycloneDX(f cdx.BOMFileFormat) parser {
	return func(b []byte) interface{} {
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(bytes.NewReader(b), f)
		if err := decoder.Decode(bom); err != nil || bom.Version == 0 {
			return nil
		}
		return bom
	}
}

func serializeCycloneDX(f cdx.BOMFileFormat) serializer {
	return func(bom interface{}, writer io.Writer) error {
		var cdxBOM *cdx.BOM
		var ok bool
		if cdxBOM, ok = bom.(*cdx.BOM); !ok {
			return errors.New("given bom must be CycloneDX")
		}
		return cdx.NewBOMEncoder(writer, f).Encode(cdxBOM)
	}
}
