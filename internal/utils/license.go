/*
 * © 2023 Snyk Limited All rights reserved.
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

package utils

import (
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

// License is one license string from ecosyste.ms, resolved against the SPDX
// license list.
type License struct {
	// SPDXID is the normalized SPDX expression, or a "LicenseRef-" identifier
	// when Raw is not valid SPDX.
	SPDXID string

	// Raw is the original ecosyste.ms string, set only when it is not valid
	// SPDX and had to be captured as a LicenseRef.
	Raw string
}

// ClassifyLicenses resolves each license string against the SPDX license list.
// ecosyste.ms passes package metadata through as-is, and registries such as
// Maven accept any string, so the result is not always valid SPDX. Strings that
// are not get turned into LicenseRef- identifiers, so that the documents parlay
// emits still validate. See https://github.com/snyk/parlay/issues/80.
func ClassifyLicenses(licenses []string) []License {
	out := make([]License, 0, len(licenses))
	seen := make(map[string]bool, len(licenses))

	for _, raw := range licenses {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		// Both only carry meaning on their own, and neither can be joined into
		// an expression, so a package saying nothing keeps saying nothing.
		if raw == "NONE" || raw == "NOASSERTION" {
			continue
		}

		if seen[raw] {
			continue
		}
		seen[raw] = true

		// Refs are rejected so that a ref arriving from ecosyste.ms is captured
		// as extracted licensing info here, rather than dangling undefined.
		normalized, invalid := spdxexp.ValidateAndNormalizeLicensesWithOptions(
			[]string{raw},
			spdxexp.ValidateLicensesOptions{FailAllLicenseRefs: true, FailAllDocumentRefs: true},
		)
		if len(invalid) == 0 && len(normalized) == 1 {
			out = append(out, License{SPDXID: normalized[0]})
			continue
		}

		id := licenseRefID(raw)
		if id == "" {
			// ponytail: nothing left to identify the license by, so drop it
			// rather than emit a meaningless shared ref.
			continue
		}
		out = append(out, License{SPDXID: id, Raw: raw})
	}

	return out
}

// LicenseExpression joins license identifiers into one SPDX license expression.
func LicenseExpression(ids []string) string {
	switch len(ids) {
	case 0:
		return ""
	case 1:
		return ids[0]
	default:
		return "(" + strings.Join(ids, " OR ") + ")"
	}
}

// licenseRefID builds a "LicenseRef-[idstring]" identifier from a license
// string. An idstring is limited to letters, numbers, "." and "-", so anything
// else collapses to a "-". Two strings differing only in stripped characters
// therefore share a ref, which is fine: they dedupe to a single entry.
func licenseRefID(raw string) string {
	// An incoming ref keeps its name rather than gaining a second prefix.
	id := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '-'
		}
	}, strings.TrimPrefix(raw, "LicenseRef-"))

	// Collapse the runs left behind by the mapping above.
	for strings.Contains(id, "--") {
		id = strings.ReplaceAll(id, "--", "-")
	}
	id = strings.Trim(id, "-")

	if id == "" {
		return ""
	}
	return "LicenseRef-" + id
}

// IsIdentifier reports whether the license is a single SPDX license identifier,
// the only form CycloneDX can carry in a license id field.
func (l License) IsIdentifier() bool {
	return l.Raw == "" && !strings.ContainsAny(l.SPDXID, " ()")
}

// DisambiguateLicenseRef derives a distinct identifier for a license string
// that sanitizes down to an identifier already taken by a different string.
// Without it the two would share one extracted licensing info entry, which
// would put packages under a license they are not under.
func DisambiguateLicenseRef(id, raw string) string {
	h := fnv.New32a()
	h.Write([]byte(raw))
	return fmt.Sprintf("%s-%08x", id, h.Sum32())
}
