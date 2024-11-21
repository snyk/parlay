package snyk

import (
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"

	"github.com/snyk/parlay/lib/sbom"
	"github.com/snyk/parlay/snyk/issues"
)

type Service interface {
	EnrichSBOM(*sbom.SBOMDocument) *sbom.SBOMDocument
	GetPackageVulnerabilities(*packageurl.PackageURL) (*issues.FetchIssuesPerPurlResponse, error)
}

type serviceImpl struct {
	cfg    *Config
	logger *zerolog.Logger
}

var _ Service = (*serviceImpl)(nil)

func NewService(cfg *Config, logger *zerolog.Logger) Service {
	return &serviceImpl{cfg, logger}
}

func (svc *serviceImpl) EnrichSBOM(doc *sbom.SBOMDocument) *sbom.SBOMDocument {
	return EnrichSBOM(svc.cfg, doc, svc.logger)
}

func (svc *serviceImpl) GetPackageVulnerabilities(purl *packageurl.PackageURL) (*issues.FetchIssuesPerPurlResponse, error) {
	auth, err := svc.getAuth()
	if err != nil {
		return nil, err
	}

	orgID, err := svc.getOrgID(auth)
	if err != nil {
		return nil, err
	}

	return GetPackageVulnerabilities(svc.cfg, purl, auth, orgID, svc.logger)
}

func (svc *serviceImpl) getAuth() (*securityprovider.SecurityProviderApiKey, error) {
	return AuthFromToken(svc.cfg.APIToken)
}

func (svc *serviceImpl) getOrgID(auth *securityprovider.SecurityProviderApiKey) (*uuid.UUID, error) {
	return SnykOrgID(svc.cfg, auth)
}
