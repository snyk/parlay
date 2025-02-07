# Parlay

[![CI](https://github.com/snyk/parlay/actions/workflows/ci.yml/badge.svg)](https://github.com/snyk/parlay/actions/workflows/ci.yml)
[![Security](https://github.com/snyk/parlay/actions/workflows/security.yml/badge.svg)](https://github.com/snyk/parlay/actions/workflows/security.yml)

## Enriching SBOMs

`parlay` will take a CycloneDX (JSON, XML) or SPDX 2.3 (JSON) document and enrich it with information taken from external services. At present this includes:

* [ecosyste.ms](https://ecosyste.ms)
* [Snyk](https://snyk.io)
* [OpenSSF Scorecard](https://securityscorecards.dev/)

By enrich, we mean add additional information. You put in an SBOM, and you get a richer SBOM back. In many cases SBOMs have a minimum of information, often just the name and version of a given package. By enriching that with additional information we can make better decisions about the packages we're using.

## Enriching with ecosyste.ms

Let's take a simple CycloneDX SBOM of a Javascript application. Using `parlay` we enrich it using data from [ecosyste.ms](https://ecosyste.ms), adding information about the package license, external links, the maintainer and more.

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
$ cat testing/sbom.cyclonedx.json | parlay ecosystems enrich - | jq
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

What about with SPDX? Let's take an SBOM containing a list of packages like so:

```json
{
  "name": "concat-map",
  "SPDXID": "SPDXRef-7-concat-map-0.0.1",
  "versionInfo": "0.0.1",
  "downloadLocation": "NOASSERTION",
  "copyrightText": "NOASSERTION",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceType": "purl",
      "referenceLocator": "pkg:npm/concat-map@0.0.1"
    }
  ]
}
```

Running `parlay ecosystems enrich <sbom.spdx.json>` will add additional information:

```diff
{
  "name": "concat-map",
  "SPDXID": "SPDXRef-7-concat-map-0.0.1",
  "versionInfo": "0.0.1",
  "downloadLocation": "NOASSERTION",
+  "homepage": "https://github.com/ljharb/concat-map",
+  "licenseConcluded": "MIT",
  "copyrightText": "NOASSERTION",
+  "description": "concatenative mapdashery",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceType": "purl",
      "referenceLocator": "pkg:npm/concat-map@0.0.1"
    }
  ]
```

There are a few other utility commands for ecosyste.ms as well. The first returns raw JSON information about a specific package from ecosyste.ms:

```
parlay ecosystems package pkg:npm/snyk
```

You can also return raw JSON information about a specific repository:

```
parlay ecosystems repo https://github.com/open-policy-agent/conftest
```

### License data

parlay enriches components and packages with their license information from ecosyste.ms on a best-effort basis. It prefers the license data of the package version at hand; however, it may not always be possible to retrieve the license for a specific version (see [ecosyste.ms issue here](https://github.com/ecosyste-ms/packages/issues/1027) for more info). In this case, parlay will fall back to enriching with the license data of the package's latest release. In rare cases — where the licensing model of a package changed over time — this may result in license data inaccuracies.


## Enriching with Snyk

`parlay` can also enrich an SBOM with Vulnerability information from Snyk.

It's important to note vulnerability data is moment-in-time information. By adding vulnerability information directly to the SBOM this makes the SBOM moment-in-time too.

Note the Snyk commands require you to be a Snyk customer, and require passing a valid Snyk API token in the `SNYK_TOKEN` environment variable.

The API base url can be set using the `SNYK_API` environment variable, and if missing it will default to `https://api.snyk.io`.

```
parlay snyk enrich testing/sbom.cyclonedx.json
```

Snyk will add a new [vulnerability](https://cyclonedx.org/docs/1.4/json/#vulnerabilities) attribute to the SBOM, for example:

```json
"vulnerabilities": [
  {
    "bom-ref": "68-subtext@6.0.12",
    "id": "SNYK-JS-SUBTEXT-467257",
    "ratings": [
      {
        "source": {
          "name": "Snyk",
          "url": "https://security.snyk.io"
        },
        "score": 7.5,
        "severity": "high",
        "method": "CVSSv31",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
      }
    ],
    "cwes": [
      400
    ],
    "description": "Denial of Service (DoS)",
    "detail": "...",
    "advisories": [
      {
        "title": "GitHub Commit",
        "url": "https://github.com/brave-intl/subtext/commit/9557c115b1384191a0d6e4a9ea028fedf8b44ae6"
      },
      {
        "title": "GitHub Issue",
        "url": "https://github.com/hapijs/subtext/issues/72"
      },
      {
        "title": "NPM Security Advisory",
        "url": "https://www.npmjs.com/advisories/1168"
      }
    ],
    "created": "2019-09-19T10:25:11Z",
    "updated": "2020-12-14T14:41:09Z"
  }
```

For SPDX, vulnerability informatio is added as additional `externalRefs`:

```json
{
  "referenceCategory": "SECURITY",
  "referenceType": "advisory",
  "referenceLocator": "https://security.snyk.io/vuln/SNYK-JS-MINIMATCH-3050818",
  "comment": "Regular Expression Denial of Service (ReDoS)"
},
{
  "referenceCategory": "SECURITY",
  "referenceType": "advisory",
  "referenceLocator": "https://security.snyk.io/vuln/SNYK-JS-MINIMATCH-1019388",
  "comment": "Regular Expression Denial of Service (ReDoS)"
}
```

Return raw JSON information about vulnerabilities in a specific package from Snyk:

```
parlay snyk package pkg:npm/sqliter@1.0.1
```

## Enriching with OpenSSF Scorecard

The [OpenSSF Scorecard project](https://securityscorecards.dev/) tests various aspects of a projects security posture and provides a score. `parlay` supports added a link to this data with the `parlay scorecard enrich` command.


You can use this like so:

```
parlay scorecard enrich testing/sbom2.cyclonedx.json
```

This will currently add an external reference to the [Scorecard API](https://api.securityscorecards.dev/) which can be used to retrieve the full scorecard.

```json
{
  "bom-ref": "103-org.springframework:spring-webmvc@5.3.3",
  "type": "library",
  "name": "org.springframework:spring-webmvc",
  "version": "5.3.3",
  "purl": "pkg:maven/org.springframework/spring-webmvc@5.3.3",
  "externalReferences": [
    {
      "url": "https://api.securityscorecards.dev/projects/github.com/spring-projects/spring-framework",
      "comment": "OpenSSF Scorecard",
      "type": "other"
    }
  ]
},
```

We're currently looking at the best way of encoding some of the scorecard data in the SBOM itself as well.


## What about enriching with other data sources?

There are lots of other sources of package data, and it would be great to add support for them in `parlay`. Please open issues and PRs with ideas.


## Pipes!

`parlay` is a fan of stdin and stdout. You can pipe SBOMs from other tools into `parlay`, and pipe between the separate `enrich` commands too.

Maybe you want to enrich an SBOM with both ecosyste.ms and Snyk data:

```
cat testing/sbom.cyclonedx.json | ./parlay e enrich - | ./parlay s enrich - | jq
```

Maybe you want to take the output from Syft and add vulnerabilitity data?

```
syft -o cyclonedx-json nginx | parlay s enrich - | jq
```

Maybe you want to geneate an SBOM with `cdxgen`, enrich that with extra information, and test that with `bomber`:

```
cdxgen -o | parlay e enrich -  | bomber scan --provider snyk -
```

The ecosyste.ms enrichment adds license information, which Bomber then surfaces:

```
■ Ecosystems detected: gem
■ Scanning 18 packages for vulnerabilities...
■ Vulnerability Provider: Snyk (https://security.snyk.io)

■ Files Scanned
        - (sha256:701770b2317ea8cbd03aa398ecb6a0381c85beaf24d46c45665b53331816e360)

■ Licenses Found: MIT, Apache-2.0, BSD-3-Clause, Ruby
```


## Installation

`parlay` binaries are available from [GitHub Releases](https://github.com/snyk/parlay/releases). Just select the archive for your operating system and architecture. For instance, you could download for macOS ARM machines with the following, substituting `{version}` for the latest version number, for instance `0.1.4`.

```
wget https://github.com/snyk/parlay/releases/download/v{version}/parlay_Darwin_arm64.tar.gz
tar -xvf parlay_Darwin_arm64.tar.gz
```


## Supported package types

The various services used to enrich the SBOM data have data for a subset of purl types:

### Ecosystems

* `apk`
* `cargo`
* `cocoapods`
* `composer`
* `gem`
* `golang`
* `hex`
* `maven`
* `npm`
* `nuget`
* `pypi`

### Snyk

* `apk`
* `cargo`
* `cocoapods`
* `composer`
* `deb`
* `gem`
* `golang`
* `hex`
* `maven`
* `npm`
* `nuget`
* `pypi`
* `rpm`
* `swift`

### OpenSSF Scorecard

* `apk`
* `cargo`
* `cocoapods`
* `composer`
* `gem`
* `golang`
* `hex`
* `maven`
* `npm`
* `nuget`
* `pypi`

Note that Scorecard data is available only for a subset of projects from supported Git repositories. See the [Scorecard project](https://github.com/ossf/scorecard) for more information.
