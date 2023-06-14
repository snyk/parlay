package flags

import (
	"fmt"
	"strings"

	"github.com/snyk/parlay/lib/sbom"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type FormatFlagVal string

const (
	SBOMFormatCycloneDX1_4JSON = FormatFlagVal("cyclonedx+json")
	SBOMFormatCycloneDX1_4XML  = FormatFlagVal("cyclonedx+xml")

	SBOMFormatSPDX2_3JSON = FormatFlagVal("spdx2_3+json")
)

var flagToSBOMFormat = map[FormatFlagVal]sbom.SBOMFormat{
	SBOMFormatCycloneDX1_4JSON: sbom.SBOMFormatCycloneDX1_4JSON,
	SBOMFormatCycloneDX1_4XML:  sbom.SBOMFormatCycloneDX1_4XML,
	SBOMFormatSPDX2_3JSON:      sbom.SBOMFormatSPDX2_3JSON,
}

func (f *FormatFlagVal) String() string {
	return string(*f)
}

func (f *FormatFlagVal) Set(v string) error {
	switch v {
	case string(SBOMFormatCycloneDX1_4JSON), string(SBOMFormatCycloneDX1_4XML), string(SBOMFormatSPDX2_3JSON):
		*f = FormatFlagVal(v)
		return nil
	default:
		return fmt.Errorf("must be one of %s", strings.Join([]string{
			string(SBOMFormatCycloneDX1_4JSON),
			string(SBOMFormatCycloneDX1_4XML),
			string(SBOMFormatSPDX2_3JSON),
		}, ", "))
	}
}

func (f *FormatFlagVal) Type() string {
	return "<sbom-format>"
}

var _ pflag.Value = (*FormatFlagVal)(nil)

func AddFormatFlag(cmd *cobra.Command) (*FormatFlagVal, error) {
	var format FormatFlagVal

	cmd.Flags().Var(&format, "format", "Specify the given SBOM format.")

	if err := viper.BindPFlag("format", cmd.Flags().Lookup("format")); err != nil {
		return nil, err
	}

	if err := cmd.MarkFlagRequired("format"); err != nil {
		return nil, err
	}

	return &format, nil
}

func FlagToSBOMFormat(f *FormatFlagVal) *sbom.SBOMFormat {
	format := flagToSBOMFormat[*f]
	return &format
}
