# go-yosovss

[![Build and Test Status](https://github.com/shaih/go-yosovss/workflows/Build%20and%20Test/badge.svg)](https://github.com/shaih/go-yosovss/actions?query=workflow%3A%22Build+and+Test%22)
[![Lint Status](https://github.com/shaih/go-yosovss/workflows/Lint/badge.svg)](https://github.com/shaih/go-yosovss/actions?query=workflow%3ALint)

Go implementation of YOSO-style verifiable secret sharing

## Getting Started

### Requirements

- Ubuntu 20.04 (or later) or macOS 11 (or later) 
- If on macOS, [HomeBrew](https://brew.sh/) is recommended
- `go` version at least 1.15 - tested with 1.17.6
    - on Ubuntu: https://golang.org/doc/install
    - on macOS: `brew install go`
- `libsodium` 1.0.18
    - on Ubuntu: `sudo apt install libsodium-dev`
    - on macOS: `brew install libsodium`
- `swig`
    - Used in `primitives/vss` to interface with NTL
    - on Ubuntu: `sudo apt install swig`
    - on macOS: `brew install swig`
- `ntl`:
    - on Ubuntu: `sudo apt install m4 libgmp-dev libntl-dev`
    - on macOS: `brew install ntl`

### Running the project

Run:
```bash
make test
```

### Benchmarking

#### Micro-benchmarks of elliptic curve operations

```bash
cd primitives/curve25519
go test -bench .
```

#### Benchmark of the resharing protocol

See the [README for the protocol](protocols/resharing/README.md).

### Organization

* `communication`: communication layer, broadcast channel. 
  Currently this is "fake" using Go channels, there is no actual networking implemented.
  But it can easily be added.
* `msgpack`: functions helping for serializing via msgpack
* `primitives`: cryptographic primitives used by the protocol.
* `protocols/resharing`: the resharing protocol. See README.md inside

## Contribute

### Requirements

- `golangci-lint`
  - on Ubuntu: https://golangci-lint.run/usage/install/#local-installation 
    (note that you must have a single folder in your `$GOPATH` if you run the proposed command)
  - on macOS: `brew install golangci-lint`
- `gosec`
  - on Ubuntu: https://github.com/securego/gosec#local-installation
  - on macOS: `brew install gosec`
- `genny`: `go get github.com/cheekybits/genny`:
  - Used to generate files `gen-*` except `gen-codecgen.go`
  - Note that we commit those files too in case `genny` becomes unavailable
- `codecgen`: `go get -u github.com/ugorji/go/codec/codecgen`:
  - Used to improve performance of go-codec
  - Do not forget to update `protocol/resharing/auditor/codecgen.go` if adding new structures that need to be encoded

### Lint code

Run:
```bash
make lint
```

If you have error, you can try to automatically fix them:
```bash
make lint-fix
```

If using Goland or Visual Studio Code, it is recommended to use the Golangci integration:
https://golangci-lint.run/usage/integrations/

### Fixing common issues

#### Msgpack decode some struct field into nil

Re-generate the codec file:
```bash
make generate
```

#### Huge memory use

If using pprof shows nothing, the issue is most likely in the C library
(missing free from a malloc).

### Fixing common gosec issues

#### G107: Url provided to HTTP request as taint input

Verify there is no security risk and ignore using `// #nosec G107`.

#### G304: File path provided as taint input

Verify there is no security risk and ignore using `// #nosec G304`.

#### G307: Deferring a method which returns an error

##### When reading a file

```go
// #nosec G307
// no need to check error on close when reading file
defer inFile.Close()
```

#### When writing a file

Always close the file manually at the end of the function:

```go
outFile, err := os.Create(fileName)
if err != nil {
    return _, fmt.Errorf("error opening file '%s': %v", fileName, err)
}

// #nosec G307
// manually closing on success, so no need to check error again
defer outFile.Close()

// ...

if err := outFile.Close(); err != nil {
    return _, fmt.Errorf("error closing file '%s': %v", fileName, err)
}
```

## Advanced Topics

### Test Locally Github Actions

This is only if you are changing Github actions.

Use https://github.com/nektos/act

```
act
```

Note the file `.actrc` that make us use manually the real image instead of the default one.
There are 2 reasons: https://github.com/nektos/act/issues/269 and the fact that `gcc` is not included in the default image (and is needed by `cgo`)
See https://github.com/nektos/act#configuration

