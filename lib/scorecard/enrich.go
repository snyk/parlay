package scorecard

import (
	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/snyk/parlay/lib/sbom"
)

func EnrichSBOM(doc *sbom.SBOMDocument) *sbom.SBOMDocument {
	switch bom := doc.BOM.(type) {
	case *cdx.BOM:
		enrichCDX(bom)
	}

	return doc
}
