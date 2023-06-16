package sbom

import (
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type SBOMDocument struct {
	BOM    *cdx.BOM
	Format SBOMFormat

	encode encoderFn
}

var _ SBOMEncoder = (*SBOMDocument)(nil)

func (d *SBOMDocument) Encode(w io.Writer) error {
	if d.encode == nil {
		return fmt.Errorf("no encoder for format %s", d.Format)
	}

	return d.encode(w)
}
