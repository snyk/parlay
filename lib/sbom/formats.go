package sbom

type SBOMFormat string

const (
	SBOMFormatCycloneDX1_4JSON = SBOMFormat("CycloneDX 1.4 JSON")
	SBOMFormatCycloneDX1_4XML  = SBOMFormat("CycloneDX 1.4 XML")
)
