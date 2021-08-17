package curve25519

import (
	"fmt"
	"testing"
)

func BenchmarkRandomScalar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = RandomScalar()
	}
}

func BenchmarkSodium32RandomBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = sodium32RandomBytes()
	}
}

func BenchmarkMultPointScalar(b *testing.B) {
	p := RandomPoint()
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MultPointScalar(p, n)
	}
}

func BenchmarkMultBaseGPointScalar(b *testing.B) {
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MultBaseGPointScalar(n)
	}
}

func BenchmarkMultBaseGPointScalar2(b *testing.B) {
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = multBaseGPointScalar2(n)
	}
}

func BenchmarkMultBaseHPointScalar(b *testing.B) {
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = MultBaseHPointScalar(n)
	}
}

func BenchmarkDoubleMultBaseGHPointScalar(b *testing.B) {
	ng := RandomScalar()
	nh := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DoubleMultBaseGHPointScalar(ng, nh)
	}
}

func BenchmarkAddPoint(b *testing.B) {
	p := RandomPoint()
	q := RandomPoint()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AddPoint(p, q)
	}
}

func BenchmarkMultScalar(b *testing.B) {
	p := RandomScalar()
	n := RandomScalar()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MultScalar(p, n)
	}
}

func BenchmarkAddPointsNaive256(b *testing.B) {
	testCases := []struct {
		n int
	}{
		{128},
		{256},
		{512},
		{768},
		{1024},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			n := tc.n
			pts := make([]Point, n)
			for i := 0; i < n; i++ {
				pts[i] = *RandomPoint()
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = AddPointsNaive(pts)
			}
		})
	}
}

func BenchmarkAddPoints256(b *testing.B) {
	testCases := []struct {
		n int
	}{
		{128},
		{256},
		{512},
		{768},
		{1024},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			n := tc.n
			pts := make([]Point, n)
			for i := 0; i < n; i++ {
				pts[i] = *RandomPoint()
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = AddPoints(pts)
			}
		})
	}
}
