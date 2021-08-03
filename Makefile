.PHONY: generate test lint fix-lint vendor

generate:
	go generate ./...

test: generate
	go test ./...

lint: generate
	golangci-lint run
	gosec ./...

lint-fix: generate
	go fmt ./...
	golangci-lint run --fix
	gosec ./...

vendor: generate
	go mod vendor