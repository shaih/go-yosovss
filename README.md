# go-yosovss
Go implementation of YOSO-style verifiable secret sharing

## Getting Started

### Requirements

- Ubuntu 20.04 or macOS (with HomeBrew)
- `go` version at least 1.15
    - on Ubuntu: https://golang.org/doc/install
    - on macOS: `brew install go`
- `libsodium` 1.0
    - on Ubuntu: `sudo apt install libsodium-dev`
    - on macOS: `brew install libsodium`

Note: Contrary to the Algorand source code, we do not have the same requirement of traceability, so we install `libsodium` independently:
https://github.com/algorand/go-algorand/issues/20#issuecomment-506777532
rather than forking libsodium repo / using a git submodule.

### Running the project

Run:
```
go test ./...
```

## Advanced Topics

### Test Locally Github Actions

Use https://github.com/nektos/act