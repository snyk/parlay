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
	"bytes"
	"io"

	spdx_json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
)

func decodeSPDX2_3JSON(b []byte) (*spdx.Document, error) {
	return spdx_json.Read(bytes.NewReader(b))
}

func encodeSPDX2_3JSON(bom *spdx.Document) encoderFn {
	return func(w io.Writer) error {
		return spdx_json.Write(bom, w)
	}
}
