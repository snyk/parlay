build:
	@go build -v

test:
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

clients: specs
	@oapi-codegen -generate types,client -package packages specs/packages.yaml > ecosystems/packages/packages.go
	@oapi-codegen -generate types,client -package repos specs/repos.yaml > ecosystems/repos/repos.go

fmt:
	@gofmt -s -w -l .


.PHONY: build test acceptance lint cover specs clients fmt
