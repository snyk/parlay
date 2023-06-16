#!/usr/bin/env bats

@test "Not fail when testing a JavaScript SBOM" {
  run ./parlay ecosystems enrich testing/sbom.cyclonedx.json
  [ "$status" -eq 0 ]
}

@test "Not fail when testing an SBOM on stdin" {
  run bash -c "cat testing/sbom.cyclonedx.json | ./parlay ecosystems enrich -"
  [ "$status" -eq 0 ]
}

@test "Not fail when testing a Java SBOM" {
  run ./parlay ecosystems enrich testing/sbom2.cyclonedx.json
  [ "$status" -eq 0 ]
}

@test "Not fail when testing a CycloneDX XML SBOM" {
  run ./parlay ecosystems enrich testing/sbom.cyclonedx.xml
  [ "$status" -eq 0 ]
}

@test "Fail when testing a non-existent file" {
  run ./parlay ecosystems enrich not-here
  [ "$status" -eq 1 ]
}
