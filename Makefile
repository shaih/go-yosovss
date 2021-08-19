.PHONY: generate test lint fix-lint vendor

generate:
	go generate ./...
	# The following is to prevent gosec to complain about gen-codecgen.go
	# Current version of gosec does not allow to exclude generated files
	sed -i'.original' '1s%^%// #nosec\n%' protocols/resharing/auditor/gen-codecgen.go
	rm protocols/resharing/auditor/gen-codecgen.go.original

test: generate
	go test ./...

lint: generate
	golangci-lint run

lint-fix: generate
	go fmt ./...
	golangci-lint run --fix
	gosec ./...

vendor: generate
	go mod vendor