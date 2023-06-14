package sbom

import (
	"bytes"
	"io"

	spdx_json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func decodeSPDX2_3JSON(b []byte) (*SBOMDocument, error) {
	spdxBOM, err := spdx_json.Read(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	return &SBOMDocument{
		BOM:    spdxBOM,
		encode: encodeSPDX2_3JSON(spdxBOM),
	}, nil
}

func encodeSPDX2_3JSON(bom *v2_3.Document) encodeFn {
	return func(w io.Writer) error {
		return spdx_json.Write(bom, w)
	}
}
