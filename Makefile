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

.PHONY: build test acceptance lint cover
