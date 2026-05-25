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
	"encoding/base64"
	"encoding/hex"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

type integrityAlg struct {
	cdxAlg    cdx.HashAlgorithm
	spdxAlg   common.ChecksumAlgorithm
	byteCount int
}

var integrityAlgs = map[string]integrityAlg{
	"sha256": {cdx.HashAlgoSHA256, common.SHA256, 32},
	"sha512": {cdx.HashAlgoSHA512, common.SHA512, 64},
}

// parseIntegrity parses the "<alg>-<encoded>" integrity string served by
// ecosyste.ms and returns the matching CycloneDX and SPDX algorithm
// identifiers plus a lowercase hex-encoded digest value. The encoded
// portion may be raw hex (PyPI, RubyGems) or base64 (npm Subresource
// Integrity); both are normalised to hex on output.
func parseIntegrity(s string) (cdx.HashAlgorithm, common.ChecksumAlgorithm, string, bool) {
	algStr, value, found := strings.Cut(s, "-")
	if !found {
		return "", "", "", false
	}
	alg, known := integrityAlgs[strings.ToLower(algStr)]
	if !known {
		return "", "", "", false
	}

	// Hex: length is exactly 2× the digest size and decodes cleanly.
	if len(value) == alg.byteCount*2 {
		if _, err := hex.DecodeString(value); err == nil {
			return alg.cdxAlg, alg.spdxAlg, strings.ToLower(value), true
		}
	}
	// Base64 (standard or URL-safe), as used by npm SRI.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(value); err == nil && len(b) == alg.byteCount {
			return alg.cdxAlg, alg.spdxAlg, hex.EncodeToString(b), true
		}
	}
	return "", "", "", false
}
