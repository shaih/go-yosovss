package curve25519

import "testing"

func BenchmarkMultPointScalar(b *testing.B) {
	p := RandomPoint()
	n := RandomScalar()

	for i := 0; i < b.N; i++ {
		_, _ = MultPointScalar(p, n)
	}
}

func BenchmarkMultBaseGPointScalar(b *testing.B) {
	n := RandomScalar()

	for i := 0; i < b.N; i++ {
		_, _ = MultBaseGPointScalar(n)
	}
}

func BenchmarkMultBaseGPointScalar2(b *testing.B) {
	n := RandomScalar()

	for i := 0; i < b.N; i++ {
		_, _ = multBaseGPointScalar2(n)
	}
}

func BenchmarkMultBaseHPointScalar(b *testing.B) {
	n := RandomScalar()

	for i := 0; i < b.N; i++ {
		_, _ = MultBaseHPointScalar(n)
	}
}

func BenchmarkAddPoint(b *testing.B) {
	p := RandomPoint()
	q := RandomPoint()

	for i := 0; i < b.N; i++ {
		_, _ = AddPoint(p, q)
	}
}

func BenchmarkMultScalar(b *testing.B) {
	p := RandomScalar()
	n := RandomScalar()

	for i := 0; i < b.N; i++ {
		_ = MultScalar(p, n)
	}
}

func BenchmarkAddPointsNaive256(b *testing.B) {
	n := 256
	pts := make([]Point, n)
	for i := 0; i < n; i++ {
		pts[i] = *RandomPoint()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = AddPointsNaive(pts)
	}
}

func BenchmarkAddPoints256(b *testing.B) {
	n := 256
	pts := make([]Point, n)
	for i := 0; i < n; i++ {
		pts[i] = *RandomPoint()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = AddPoints(pts)
	}
}
