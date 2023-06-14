package sbom

type SBOMFormat string

const (
	// CycloneDX 1.4

	SBOMFormatCycloneDX1_4JSON = SBOMFormat("CycloneDX 1.4 JSON")
	SBOMFormatCycloneDX1_4XML  = SBOMFormat("CycloneDX 1.4 XML")

	// SPDX 2.3

	SBOMFormatSPDX2_3JSON = SBOMFormat("SPDX 2.3 JSON")
)
