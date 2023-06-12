package utils

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentifySBOM_CycloneDX_JSON(t *testing.T) {
	b := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)

	bom, _ := IdentifySBOM(b)

	assert.IsType(t, new(cdx.BOM), bom)
}

func TestIdentifySBOM_CycloneDX_XML(t *testing.T) {
	b := []byte(`<?xml version="1.0" encoding="utf-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1"></bom>`)

	bom, _ := IdentifySBOM(b)

	assert.IsType(t, new(cdx.BOM), bom)
}

func TestIdentifySBOM_Unknown(t *testing.T) {
	b := []byte(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3"}`)

	bom, _ := IdentifySBOM(b)

	require.Nil(t, bom)
}
