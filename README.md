# Parlay

[![CI](https://github.com/snyk/parlay/actions/workflows/ci.yml/badge.svg)](https://github.com/snyk/parlay/actions/workflows/ci.yml)

## Enriching SBOMs

`parlay` will take a CycloneDX document and enrich it with information taken from [ecosyste.ms](https://ecosyste.ms). This currently includes:

| Implemented | Ecosyste.ms  | CycloneDX  |
|:-:|---|---|
| :heavy_check_mark: | Homepage  | ExternalReferences type=website |
| :heavy_check_mark: | FirstReleasePublishedAt  | Properties  |
| :heavy_check_mark: | LatestReleasePublishedAt  | Properties  |
| :heavy_check_mark: | RegistryUrl | ExternalReferences type=distribution  |
| :heavy_check_mark: | RepositoryUrl | ExternalReferences type=vcs |
| :heavy_check_mark: | DocumentationUrl | ExternalReferences type=documentation |
| :heavy_check_mark: | RepoMetadata.topics | Properties |
|  | RepoMetadata.metadata.files.license | Licenses |
|  | RepoMetadata.metadata.files.license | ExternalReferences type=license |
|  | RepoMetadata.metadata.files.code_of_conduct | ExternalReferences type=other |
| :heavy_check_mark: | RepoMetadata.owner_record.name | Author |
| :heavy_check_mark: | RepoMetadata.owner_record.name | Supplier name |
| :heavy_check_mark: | RepoMetadata.owner_record.website | Supplier url |
| :heavy_check_mark: | RepoMetadata.owner_record.location | Properties  |
| :heavy_check_mark: | RepoMetadata.archived | Properties |


## Usage

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

## Ecosyste.ms utilities

_Note these commands will probably be pulled out into a separate toool, but documenting them for the moment as they make experimenting easier._

Return information on a specific package:

```
parlay ecosystems package pkg:npm/snyk
```

Return information on a specific repo:

```
parlay ecosystems repo https://github.com/open-policy-agent/conftest
```
