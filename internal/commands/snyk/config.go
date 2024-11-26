package snyk

import (
	"os"

	"github.com/snyk/parlay/lib/snyk"
)

func config() *snyk.Config {
	c := snyk.DefaultConfig()

	if t := os.Getenv("SNYK_TOKEN"); t != "" {
		c.APIToken = t
	}
	if u := os.Getenv("SNYK_API"); u != "" {
		c.SnykAPIURL = u
	}

	return c
}
