package auditor

import (
	"fmt"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDLProveCorrect(t *testing.T) {
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
			stmt, wit, err := genStmtWit(n)
			require.NoError(err)

			// Generate the proof
			proof, err := DLProve(stmt, wit)
			require.NoError(err)

			// Verify it
			err = DLVerify(stmt, proof)
			assert.NoError(err)
		})
	}
}

func TestDLProveIncorrect(t *testing.T) {
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
			stmt, wit, err := genStmtWit(n)
			require.NoError(err)

			// Generate the proof
			proof, err := DLProve(stmt, wit)
			require.NoError(err)

			// Break the proof
			proof.Resp[0] = *curve25519.NegateScalar(&proof.Resp[0])

			// Verify it
			err = DLVerify(stmt, proof)
			assert.Error(err)
		})
	}
}

// genStmtWit generates a random valid statement and witness
func genStmtWit(n int) (stmt DLStatement, wit DLWitness, err error) {
	vcParams, err := feldman.GenerateVCParams(n - 1)
	if err != nil {
		return DLStatement{}, DLWitness{}, fmt.Errorf("error generating vcparams: %w", err)
	}

	xLog := make([]curve25519.Scalar, n)
	x := make([]curve25519.PointXY, n)
	for i := 0; i < n; i++ {
		xLog[i] = *curve25519.RandomScalar()
		xi, err := curve25519.MultPointXYScalar(&vcParams.Bases[i], &xLog[i])
		if err != nil {
			return DLStatement{}, DLWitness{}, err
		}
		x[i] = *xi
	}

	stmt = DLStatement{
		G: vcParams.Bases,
		X: x,
	}

	wit = DLWitness{
		XLog: xLog,
	}
	return stmt, wit, err
}
