package vss

import (
	"fmt"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generatorMatrix(n, t int) *curve25519.ScalarMatrix {
	gen := curve25519.NewScalarMatrix(t, n+1)

	for j := 0; j <= n; j++ {
		jScalar := curve25519.GetScalar(uint64(j))
		// first row is just 1
		gen.Set(0, j, &curve25519.ScalarOne)
		// other columns are product of previous row with j
		for i := 1; i < t; i++ {
			gen.Set(i, j, curve25519.MultScalar(gen.At(i-1, j), jScalar))
		}
	}

	return gen
}

func TestComputeParityMatrix1x1(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	m, err := ComputeParityMatrix(1, 1)

	require.NoError(err)
	require.Equal(2, m.Rows(), "expecting 2 rows")
	require.Equal(1, m.Columns(), "expecting 1 column")
	assert.True(
		curve25519.ScalarEqual(
			curve25519.AddScalar(m.At(0, 0), m.At(1, 0)),
			&curve25519.ScalarZero,
		),
	)
}

func TestComputeParityMatrix(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	testCases := []struct {
		n int
		t int
	}{
		{5, 3},
		{5, 5},
		{5, 1},
		{10, 7},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d,t=%d", tc.n, tc.t), func(t *testing.T) {
			gen := generatorMatrix(tc.n, tc.t)

			m, err := ComputeParityMatrix(tc.n, tc.t)

			require.NoError(err)
			require.Equal(tc.n+1, m.Rows(), "expecting 2 rows")
			require.Equal(tc.n+1-tc.t, m.Columns(), "expecting 1 column")

			prod, err := curve25519.ScalarMatrixMul(gen, m)
			require.NoError(err)
			assert.True(prod.IsZero(), "product of generator matrix and parity check matrix should be 0")

			// Test that incorrect code words are rejected
			// just add 1 to (0,0) in gen (not ideal but should catch most issues)
			gen.Set(0, 0, curve25519.AddScalar(gen.At(0, 0), &curve25519.ScalarOne))
			prod, err = curve25519.ScalarMatrixMul(gen, m)
			require.NoError(err)
			assert.False(prod.IsZero(),
				"product of incorrect generator matrix and parity check matrix should not be 0")
		})
	}
}
