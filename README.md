# Parlay

[![CI](https://github.com/snyk/parlay/actions/workflows/ci.yml/badge.svg)](https://github.com/snyk/parlay/actions/workflows/ci.yml)

## Enriching SBOMs

`parlay` will take a CycloneDX document and enrich it with information taken from external services. At present this includes:

* [ecosyste.ms](https://ecosyste.ms)
* [Snyk](https://snyk.io)

By enrich, we mean add additional information. In many cases SBOMs have a minimum of information, often just the name of version of a given package. By enriching that with additional information we can make better decisions about the packages we're using.

## A quick example

Let's take a simple SBOM of a Javascript application. Using `parlay` we enrich it using data from [ecosyste.ms](https://ecosyste.ms), adding information about the package license, external links, the maintainer and more.

```
$ cat testing/sbom.cyclonedx.json
...
{
	"bom-ref": "68-subtext@6.0.12",
	"type": "library",
	"name": "subtext",
	"version": "6.0.12",
	"purl": "pkg:npm/subtext@6.0.12"
}
...
$ cat testing/sbom.cyclonedx.json | parlay e enrich - | jq
...
{
	"bom-ref": "68-subtext@6.0.12",
	"type": "library",
	"supplier": {
		"name": "hapi.js",
		"url": [
			"https://hapi.dev"
		]
	},
	"author": "hapi.js",
	"name": "subtext",
	"version": "6.0.12",
	"description": "HTTP payload parsing",
	"licenses": [
		{
			"expression": "BSD-3-Clause"
		}
	],
	"purl": "pkg:npm/subtext@6.0.12",
	"externalReferences": [
		{
			"url": "https://github.com/hapijs/subtext",
			"type": "website"
		},
		{
			"url": "https://www.npmjs.com/package/subtext",
			"type": "distribution"
		},
		{
			"url": "https://github.com/hapijs/subtext",
			"type": "vcs"
		}
	],
	"properties": [
		{
			"name": "ecosystems:first_release_published_at",
			"value": "2014-09-29T01:56:03Z"
		},
		{
			"name": "ecosystems:latest_release_published_at",
			"value": "2019-01-31T19:36:58Z"
		}
	]
}
...
```

## Usage

Return raw JSON information about a specific package from ecosyste.ms:

```
parlay ecosystems package pkg:npm/snyk
```

Return raw JSON information about a specific repository from ecosyste.ms:

```
parlay ecosystems repo https://github.com/open-policy-agent/conftest
```

Return raw JSON information about vulnerabilities in a specific package from Snyk:

```
parlay snyk package pkg:npm/sqliter@1.0.1
```

Enrich an SBOM with vulnerability information from Snyk

```
parlay snyk enrich testing/sbom.cyclonedx.json
```

Note that `parlay` is a fan of stdin and stdout. You can pipe SBOMs from other tools into `parlay`, and pipe between the separate `enrich` commands too. 

Run `parlay --help` for full instructions.

Note the Snyk commands require you to be a Snyk customer, and require passing a valid Snyk API token in the `SNYK_TOKEN` environment variable.


