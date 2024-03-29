package curve25519

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkIsOnCurveXY(b *testing.B) {
	p := RandomPointXY()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsOnCurveXY(p)
	}
}

func BenchmarkMultPointXYScalar(b *testing.B) {
	p := RandomPointXY()
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MultPointXYScalar(p, n)
	}
}

func BenchmarkMultBaseGPointXYScalar(b *testing.B) {
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MultBaseGPointXYScalar(n)
	}
}

func BenchmarkMultBaseHPointXYScalar(b *testing.B) {
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MultBaseHPointXYScalar(n)
	}
}

func BenchmarkDoubleMultBaseGHPointXYScalar(b *testing.B) {
	ng := RandomScalar()
	nh := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DoubleMultBaseGHPointXYScalar(ng, nh)
	}
}

func BenchmarkAddPointXY(b *testing.B) {
	p := RandomPointXY()
	q := RandomPointXY()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AddPointXY(p, q)
	}
}

func BenchmarkAddPointsXYNaive(b *testing.B) {
	testCases := []struct {
		n int
	}{
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
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			n := tc.n
			pts := make([]PointXY, n)
			for i := 0; i < n; i++ {
				pts[i] = *RandomPointXY()
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = AddPointsXYNaive(pts)
			}
		})
	}
}

func BenchmarkAddPointsXY(b *testing.B) {
	testCases := []struct {
		n int
	}{
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
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			n := tc.n
			pts := make([]PointXY, n)
			for i := 0; i < n; i++ {
				pts[i] = *RandomPointXY()
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = AddPointsXY(pts)
			}
		})
	}
}

func BenchmarkAddPointsXYCheckOnCurve(b *testing.B) {
	testCases := []struct {
		n int
	}{
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
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			n := tc.n
			pts := make([]PointXY, n)
			for i := 0; i < n; i++ {
				pts[i] = *RandomPointXY()
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = AddPointsXYCheckOnCurve(pts)
			}
		})
	}
}

// GenBenchmarkMultiMultPointXYScalar allows to test easily both the constant-time and the var-time
// version of the multi-mult point/scalar functions
// see BenchmarkMultiMultPointXYScalarVarTime and BenchmarkMultiMultPointXYScalar
func GenBenchmarkMultiMultPointXYScalar(b *testing.B, f func(p []PointXY, n []Scalar) (*PointXY, error)) {
	testCases := []struct {
		n int
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
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			require := require.New(b)
			n := tc.n
			pts := make([]PointXY, n)
			scs := make([]Scalar, n)
			for i := 0; i < n; i++ {
				pts[i] = *RandomPointXY()
				scs[i] = *RandomScalar()
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := f(pts, scs)
				require.NoError(err)
			}
		})
	}
}

func BenchmarkMultiMultPointXYScalarVarTime(b *testing.B) {
	GenBenchmarkMultiMultPointXYScalar(b, MultiMultPointXYScalarVarTime)
}

func BenchmarkMultiMultPointXYScalar(b *testing.B) {
	GenBenchmarkMultiMultPointXYScalar(b, MultiMultPointXYScalar)
}
