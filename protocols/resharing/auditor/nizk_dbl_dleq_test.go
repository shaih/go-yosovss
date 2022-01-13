package auditor

import (
	"fmt"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDblDLEqProveCorrect(t *testing.T) {
	testCases := []struct {
		n int
	}{
		{1},
		{2},
		{5},
		{10},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n

			// Create a valid statement
			stmt, wit, err := genDblDLEqStmtWit(n)
			require.NoError(err)

			// Generate the proof
			proof, err := DblDLEqProve(stmt, wit)
			require.NoError(err)

			// Verify it
			err = DblDLEqVerify(stmt, proof)
			assert.NoError(err)
		})
	}
}

func TestDblDLEqProveIncorrect(t *testing.T) {
	testCases := []struct {
		n int
	}{
		{1},
		{2},
		{5},
		{10},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n

			// Create a valid statement
			stmt, wit, err := genDblDLEqStmtWit(n)
			require.NoError(err)

			// Test breaking in way 1
			// Generate the proof
			proof, err := DblDLEqProve(stmt, wit)
			require.NoError(err)

			// Break the proof in one way
			proof.RespG[0] = *curve25519.NegateScalar(&proof.RespG[0])

			// Verify it
			err = DblDLEqVerify(stmt, proof)
			assert.Error(err)

			// Test breaking in way 2
			// Generate the proof
			proof, err = DblDLEqProve(stmt, wit)
			require.NoError(err)

			// Break the proof
			proof.RespH[n-1] = *curve25519.NegateScalar(&proof.RespH[n-1])

			// Verify it
			err = DblDLEqVerify(stmt, proof)
			assert.Error(err)
		})
	}
}

// genDblDLEqStmtWit generates a random valid statement and witness
func genDblDLEqStmtWit(n int) (stmt DblDLEqStatement, wit DblDLEqWitness, err error) {
	vcParams, err := feldman.GenerateVCParams(2 * n)
	if err != nil {
		return DblDLEqStatement{}, DblDLEqWitness{}, fmt.Errorf("error generating vcparams: %w", err)
	}

	x := make([]curve25519.Scalar, n)
	y := make([]curve25519.Scalar, n)
	z := make([]curve25519.PointXY, n)
	zPrime := make([]curve25519.PointXY, n)
	for i := 0; i < n; i++ {
		x[i] = *curve25519.RandomScalar()
		y[i] = *curve25519.RandomScalar()

		zi, err := curve25519.DoubleMultBaseGHPointXYScalar(
			&x[i], &y[i],
		)
		if err != nil {
			return DblDLEqStatement{}, DblDLEqWitness{}, err
		}
		z[i] = *zi

		ziPrime, err := curve25519.MultiMultPointXYScalar(
			[]curve25519.PointXY{vcParams.Bases[i], vcParams.Bases[n+i]},
			[]curve25519.Scalar{x[i], y[i]},
		)
		if err != nil {
			return DblDLEqStatement{}, DblDLEqWitness{}, err
		}
		zPrime[i] = *ziPrime
	}

	stmt = DblDLEqStatement{
		G:      vcParams.Bases[:n],
		H:      vcParams.Bases[n:],
		Z:      z,
		ZPrime: zPrime,
	}

	wit = DblDLEqWitness{
		X: x,
		Y: y,
	}
	return stmt, wit, err
}
