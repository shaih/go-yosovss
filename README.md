# go-yosovss
Go implementation of YOSO-style verifiable secret sharing

## Getting Started

### Requirements

- Ubuntu 20.04 or macOS 
- If on macOS, [HomeBrew](https://brew.sh/) is recommended
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
```bash
make test
```

## Contribute

### Requirements

- `golangci-lint`
    - on Ubuntu: https://golangci-lint.run/usage/install/#local-installation 
      (note that you must have a single folder in your `$GOPATH` if you run the proposed command)
    - on macOS: `brew install golangci-lint`
- `gosec`
    - on Ubuntu: https://github.com/securego/gosec#local-installation
    - on macOS: `brew install gosec`

### Lint code

Run:
```bash
make lint
```

If you have error, you can try to automatically fix them:
```bash
make lint-fix
```

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
