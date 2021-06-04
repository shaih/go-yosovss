.PHONY: test lint fix-lint vendor

test:
	go test ./...

lint:
	golangci-lint run
	gosec ./...

lint-fix:
	golangci-lint run --fix
	gosec ./...

vendor:
	go mod vendor