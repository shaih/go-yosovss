//go:build generate
// +build generate

package resharing

//go:generate codecgen -o gen-codecgen.go nizk_dl.go nizk_dbl_dleq.go step1_dealing.go step2_verification.go step3_resolution.go step4_resolution.go verifier_proof.go
//go:generate gofmt -w gen-codecgen.go
