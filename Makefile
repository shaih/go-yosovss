.PHONY: generate test lint fix-lint vendor gosec

generate:
	go generate ./...
	# The following is to prevent gosec to complain about gen-codecgen.go
	# It adds a first line `// #nosec`
	# Current version of gosec does not allow to exclude generated files
	sed -i'.original' '1 i\// #nosec%' protocols/resharing/auditor/gen-codecgen.go
	rm protocols/resharing/auditor/gen-codecgen.go.original

test: generate
	go test ./...

lint: generate gosec
	golangci-lint run

gosec: generate
	gosec ./...

lint-fix: generate gosec
	go fmt ./...
	golangci-lint run --fix

vendor: generate
	go mod vendor
