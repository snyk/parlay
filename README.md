# Parlay

[![CI](https://github.com/snyk/parlay/actions/workflows/ci.yml/badge.svg)](https://github.com/snyk/parlay/actions/workflows/ci.yml)

## Enrich SBOMs

This will take a CycloneDX document and add descriptions to the component taken from [ecosyste.ms](https://ecosyste.ms).

```
$ cat testing/sbom.cyclonedx.json
...
{"bom-ref":"68-subtext@6.0.12","type":"library","name":"subtext","version":"6.0.12","purl":"pkg:npm/subtext@6.0.12"}
...
$ cat testing/sbom.cyclonedx.json | parlay enrich -
...
{"bom-ref":"68-subtext@6.0.12","type":"library","name":"subtext","version":"6.0.12","description":"Tiny millisecond conversion utility","purl":"pkg:npm/subtext@6.0.12"}
...
```

This isn't _that_ useful. But demonstrates the concept of enrichment nicely.

## TODO

Not a comprehensive list, but a few things that need work if we want to share more widely.

* Nice output formatting
* Useful enrichments (eg. license information)
* Map ecosyste.ms data to CycloneDX schema
* Enrichment using other backends, eg. ClearlyDefined or deps.dev
* UI for `enrich` command

## Ecosyste.ms utilities

_Note these commands will probably be pulled out into a separate toool, but documenting them for the moment as they make experimenting easier._

Return information on a specific package:

```
parlay package pkg:npm/snyk
```

Return information on a specific repo:

```
parlay repo https://github.com/open-policy-agent/conftest | jq
```
