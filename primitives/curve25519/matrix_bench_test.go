package curve25519

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkScalarMatrixVectorMul(b *testing.B) {
	testCases := []struct {
		n int
	}{
		{64},
		{128},
		{256},
		{512},
		{1024},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			require := require.New(b)

			m := NewScalarMatrix(tc.n, tc.n)
			v := NewScalarMatrix(tc.n, 1)
			err := m.Random()
			require.NoError(err)
			err = v.Random()
			require.NoError(err)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = ScalarMatrixMul(m, v)
			}
		})
	}
}

func BenchmarkScalarMatrixVectorMulNaive(b *testing.B) {
	testCases := []struct {
		n int
	}{
		{64},
		{128},
		{256},
		{512},
		{1024},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("n=%d", tc.n), func(b *testing.B) {
			require := require.New(b)

			m := NewScalarMatrix(tc.n, tc.n)
			v := NewScalarMatrix(tc.n, 1)
			err := m.Random()
			require.NoError(err)
			err = v.Random()
			require.NoError(err)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = ScalarMatrixMulNaive(m, v)
			}
		})
	}
}
