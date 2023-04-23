#!/usr/bin/env bats

@test "Not fail when testing a JavaScript SBOM" {
  run ./parlay enrich testing/sbom.cyclonedx.json
  [ "$status" -eq 0 ]
}

@test "Not fail when testing a Java SBOM" {
  run ./parlay enrich testing/sbom2.cyclonedx.json
  [ "$status" -eq 0 ]
}

@test "Fail when testing a non-existent file" {
  run ./parlay enrich not-here
  [ "$status" -eq 1 ]
}
