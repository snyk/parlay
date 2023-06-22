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

package sbom

import (
	"fmt"
	"io"
)

type SBOMDocument struct {
	BOM    interface{}
	Format SBOMFormat

	encode encoderFn
}

var _ SBOMEncoder = (*SBOMDocument)(nil)

func (d *SBOMDocument) Encode(w io.Writer) error {
	if d.encode == nil {
		return fmt.Errorf("no encoder for format %s", d.Format)
	}

	return d.encode(w)
}
