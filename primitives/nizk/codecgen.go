//go:build generate
// +build generate

package auditor

//go:generate codecgen -o gen-codecgen.go dl.go
//go:generate gofmt -w gen-codecgen.go
