/*
 * © 2026 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ecosystems

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/stretchr/testify/assert"
)

func TestParseIntegrity_PyPIHex(t *testing.T) {
	// PyPI/RubyGems serve "<alg>-<hex>" — fastapi 0.115.0 from the issue probe.
	cdxAlg, spdxAlg, value, ok := parseIntegrity(
		"sha256-17ea4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631",
	)

	assert.True(t, ok)
	assert.Equal(t, cdx.HashAlgoSHA256, cdxAlg)
	assert.Equal(t, common.SHA256, spdxAlg)
	assert.Equal(t,
		"17ea4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631",
		value,
	)
}

func TestParseIntegrity_RejectsBadInput(t *testing.T) {
	// Each case is a string the parser must report as unparseable so the
	// outer loop can debug-log and skip rather than emit a bogus hash.
	cases := map[string]string{
		"empty":            "",
		"no separator":     "sha256abcd",
		"unknown alg":      "sha999-deadbeef",
		"truncated hex":    "sha256-deadbeef",
		"hex wrong chars":  "sha256-zzzz4276b66cf0ecf3a8f10df1e34d40fe26be590ca1e25b1c33a0ff05451631",
		"base64 wrong len": "sha512-AAAA",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, _, ok := parseIntegrity(input)
			assert.False(t, ok)
		})
	}
}

func TestParseIntegrity_NPMSubresourceIntegrity(t *testing.T) {
	// npm serves SRI "<alg>-<base64>". Parser must decode to hex.
	cdxAlg, spdxAlg, value, ok := parseIntegrity(
		"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==",
	)

	assert.True(t, ok)
	assert.Equal(t, cdx.HashAlgoSHA512, cdxAlg)
	assert.Equal(t, common.SHA512, spdxAlg)
	assert.Equal(t,
		"9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
		value,
	)
}
