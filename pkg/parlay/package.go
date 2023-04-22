package parlay

import (
	"context"
	"fmt"
	"net/url"

	"github.com/snyk/parlay/pkg/ecosystems/packages"

	"github.com/package-url/packageurl-go"
)

const server = "https://packages.ecosyste.ms/api/v1"

func GetPackageData(purl packageurl.PackageURL) (*packages.GetRegistryPackageResponse, error) {
	client, err := packages.NewClientWithResponses(server)
	if err != nil {
		return nil, err
	}

	// Ecosyste.ms has a purl based API, but it's much slower
	//p := purl.ToString()
	//params := packages.LookupPackageParams{Purl: &p}
	//resp, err := client.LookupPackageWithResponse(context.Background(), &params)

	// Currently doesn't deal with namespaced packages yet
	mapping := map[string]string{
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
	}

	var name string
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

	resp, err := client.GetRegistryPackageWithResponse(context.Background(), mapping[purl.Type], name)

	if err != nil {
		return nil, err
	}
	return resp, nil
}
