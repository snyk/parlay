package flags

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type SBOMFormat string

const (
	SBOMFormatCycloneDX1_4JSON = SBOMFormat("cyclonedx+json")
	SBOMFormatCycloneDX1_4XML  = SBOMFormat("cyclonedx+xml")
)

func (f *SBOMFormat) String() string {
	return string(*f)
}

func (f *SBOMFormat) Set(v string) error {
	switch v {
	case string(SBOMFormatCycloneDX1_4JSON), string(SBOMFormatCycloneDX1_4XML):
		*f = SBOMFormat(v)
		return nil
	default:
		return fmt.Errorf("must be one of %s", strings.Join([]string{
			string(SBOMFormatCycloneDX1_4JSON),
			string(SBOMFormatCycloneDX1_4XML),
		}, ", "))
	}
}

func (f *SBOMFormat) Type() string {
	return "<sbom-format>"
}

var _ pflag.Value = (*SBOMFormat)(nil)

func AddFormatFlag(cmd *cobra.Command) (*SBOMFormat, error) {
	var format SBOMFormat

	cmd.Flags().Var(&format, "format", "Specify the given SBOM format.")

	if err := viper.BindPFlag("format", cmd.Flags().Lookup("format")); err != nil {
		return nil, err
	}

	if err := cmd.MarkFlagRequired("format"); err != nil {
		return nil, err
	}

	return &format, nil
}
