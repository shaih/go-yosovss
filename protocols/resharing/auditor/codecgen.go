//go:build generate
// +build generate

package auditor

//go:generate codecgen -o gen-codecgen.go nizk_dl.go step1_dealing.go step2_verification.go step3_resolution.go step4_resolution.go verifier_proof.go
//go:generate gofmt -w gen-codecgen.go
