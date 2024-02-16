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
