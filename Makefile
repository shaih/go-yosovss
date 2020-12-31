.PHONY: test lint fix-lint

test:
	go test ./...

lint:
	golangci-lint run
	gosec ./...

lint-fix:
	golangci-lint run --fix
	gosec ./...