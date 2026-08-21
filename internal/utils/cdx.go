package utils

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

func traverseComponent(comps *[]*cdx.Component, comp *cdx.Component) {
	*comps = append(*comps, comp)
	if comp.Components == nil {
		return
	}
	for i := range *comp.Components {
		traverseComponent(comps, &(*comp.Components)[i])
	}
}

func DiscoverCDXComponents(bom *cdx.BOM) []*cdx.Component {
	comps := make([]*cdx.Component, 0)
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		traverseComponent(&comps, bom.Metadata.Component)
	}

	if bom.Components != nil {
		for i := range *bom.Components {
			traverseComponent(&comps, &(*bom.Components)[i])
		}
	}
	return comps
}

// CDXLicenses renders licenses as a CycloneDX license choice list. Anything not
// usable as an SPDX identifier is named instead of identified, since CycloneDX
// cannot mix an expression and named licenses in one list. Naming is the only
// escape hatch CycloneDX offers, so a choice between licenses degrades to a
// plain list, which consumers may read as all of them applying at once.
func CDXLicenses(licenses []License) *cdx.Licenses {
	if len(licenses) == 0 {
		return nil
	}

	ids := make([]string, 0, len(licenses))
	allSPDX := true
	for _, l := range licenses {
		if l.Raw != "" {
			allSPDX = false
			break
		}
		ids = append(ids, l.SPDXID)
	}
	if allSPDX {
		return &cdx.Licenses{{Expression: LicenseExpression(ids)}}
	}

	out := make(cdx.Licenses, 0, len(licenses))
	for _, l := range licenses {
		if l.IsIdentifier() {
			out = append(out, cdx.LicenseChoice{License: &cdx.License{ID: l.SPDXID}})
			continue
		}
		name := l.Raw
		if name == "" {
			name = l.SPDXID
		}
		out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: name}})
	}
	return &out
}
