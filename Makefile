build:
	@go build -v

test:
	@go test -v ./...

acceptance: build
	@bats -r .

lint:
	@golangci-lint run --fix

.PHONY: build test acceptance lint
