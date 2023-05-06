package lib

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/snyk/parlay/ecosystems/packages"
	"github.com/snyk/parlay/snyk/issues"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/package-url/packageurl-go"
)

const server = "https://packages.ecosyste.ms/api/v1"
const snykServer = "https://api.snyk.io/rest"
const version = "2023-04-28"

func GetPackageVulnerabilities(purl packageurl.PackageURL) (*issues.FetchIssuesPerPurlResponse, error) {
	token := os.Getenv("SNYK_TOKEN")
	if token == "" {
		return nil, errors.New("Must provide a SNYK_TOKEN environment variable")
	}

	auth, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", fmt.Sprintf("token %s", token))
	if err != nil {
		return nil, err
	}

	org, err := getSnykOrg(auth)
	if err != nil {
		return nil, err
	}

	client, err := issues.NewClientWithResponses(snykServer, issues.WithRequestEditorFn(auth.Intercept))
	if err != nil {
		return nil, err
	}

	params := issues.FetchIssuesPerPurlParams{Version: version}
	resp, err := client.FetchIssuesPerPurlWithResponse(context.Background(), *org, purl.ToString(), &params)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func GetPackageData(purl packageurl.PackageURL) (*packages.GetRegistryPackageResponse, error) {
	client, err := packages.NewClientWithResponses(server)
	if err != nil {
		return nil, err
	}

	// Ecosyste.ms has a purl based API, but unfortunately slower
	// so we break the purl down to registry and name values locally
	// params := packages.LookupPackageParams{Purl: &p}
	// resp, err := client.LookupPackageWithResponse(context.Background(), &params)
	name := purlToEcosystemsName(purl)
	registry := purlToEcosystemsRegistry(purl)
	resp, err := client.GetRegistryPackageWithResponse(context.Background(), registry, name)

	if err != nil {
		return nil, err
	}
	return resp, nil
}

func purlToEcosystemsRegistry(purl packageurl.PackageURL) string {
	return map[string]string{
		"npm":       "npmjs.org",
		"golang":    "proxy.golang.org",
		"nuget":     "nuget.org",
		"hex":       "hex.pm",
		"maven":     "repo1.maven.org",
		"pypi":      "pypi.org",
		"composer":  "packagist.org",
		"gem":       "rubygems.org",
		"cargo":     "crates.io",
		"cocoapods": "cocoapod.org",
		"apk":       "alpine",
	}[purl.Type]
}

func purlToEcosystemsName(purl packageurl.PackageURL) string {
	var name string
	// npm names in the ecosyste.ms API include the purl namespace
	// followed by a / and are url encoded. Other package managers
	// appear to separate the purl namespace and name with a :
	if purl.Type == "npm" {
		if purl.Namespace != "" {
			name = url.QueryEscape(fmt.Sprintf("%s/%s", purl.Namespace, purl.Name))
		} else {
			name = purl.Name
		}
	} else {
		if purl.Namespace != "" {
			name = fmt.Sprintf("%s:%s", purl.Namespace, purl.Name)
		} else {
			name = purl.Name
		}
	}
	return name
}
