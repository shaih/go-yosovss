//+build generate

package auditor

//go:generate codecgen -o gen-codecgen.go step1_dealing.go step2_verification.go step3_resolution.go step4_witness.go step5_auditing.go step6_resolution.go
//go:generate gofmt -w gen-codecgen.go
