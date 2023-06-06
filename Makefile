# Copyright 2023 Snyk Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

build:
	@go build -v

test: lint
	@go test -cover -v ./...

acceptance: build
	@bats -r .

lint:
	@golangci-lint run --fix

cover:
	@go test ./... -coverprofile=/tmp/cover.out
	@go tool cover -html=/tmp/cover.out

specs:
	@curl --silent https://packages.ecosyste.ms/docs/api/v1/openapi.yaml -o specs/packages.yaml
	@curl --silent https://repos.ecosyste.ms/docs/api/v1/openapi.yaml -o specs/repos.yaml
	@curl --silent https://api.snyk.io/rest/openapi/2023-04-28~experimental -o specs/snyk-experimental.json
	@curl --silent https://api.snyk.io/rest/openapi/2023-04-28 -o specs/snyk.json

clients: specs
	@oapi-codegen -generate types,client -package packages specs/packages.yaml > ecosystems/packages/packages.go
	@oapi-codegen -generate types,client -package repos specs/repos.yaml > ecosystems/repos/repos.go
	@oapi-codegen -generate types,client -package users -include-tags Users specs/snyk-experimental.json > snyk/users/users.go
	@oapi-codegen -generate types,client -package issues -include-tags Issues specs/snyk.json > snyk/issues/issues.go
	sed -i '' 's/"purl", runtime.ParamLocationPath, purl/"purl", runtime.ParamLocationQuery, purl/' snyk/issues/issues.go

fmt:
	@gofmt -s -w -l .

license-update:
	@echo "==> Updating license information..."
	@rm -rf licenses
	@go-licenses save . --save_path="licenses" --ignore "github.com/snyk/snyk-ls"

.PHONY: build test acceptance lint cover specs patch clients fmt
