package curve25519

import (
	"fmt"
	"testing"
)

// GenBenchmarkPolynomialEvaluate allows to test easily both the constant-time and the var-time
// version of the multi-mult point/scalar functions
// see BenchmarkPolynomialEvaluate and BenchmarkPolynomialEvaluateNaive
func GenBenchmarkPolynomialEvaluate(b *testing.B, f func(p *Polynomial, x *Scalar) *Scalar) {
	testCases := []struct {
		d int
	}{
		{1},
		{2},
		{4},
		{8},
		{16},
		{32},
		{64},
		{128},
		{256},
		{512},
		{768},
		{1024},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("d=%d", tc.d), func(b *testing.B) {
			d := tc.d

			var p Polynomial

			p.Coefficients = make([]Scalar, d+1)
			x := RandomScalar()
			for i := 0; i <= d; i++ {
				p.Coefficients[i] = *RandomScalar()
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = f(&p, x)
			}
		})
	}
}

func BenchmarkPolynomialEvaluate(b *testing.B) {
	GenBenchmarkPolynomialEvaluate(b, func(p *Polynomial, x *Scalar) *Scalar {
		return p.Evaluate(x)
	})
}

func BenchmarkPolynomialEvaluateNaive(b *testing.B) {
	GenBenchmarkPolynomialEvaluate(b, func(p *Polynomial, x *Scalar) *Scalar {
		return p.EvaluateNaive(x)
	})
}
