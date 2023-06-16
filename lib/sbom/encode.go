package sbom

import "io"

type (
	SBOMEncoder interface {
		Encode(w io.Writer) error
	}

	encoderFn func(io.Writer) error
)
