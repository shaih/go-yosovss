package auditor

import (
	"fmt"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateDealerSharesCommitmentsValid checks that comC is valid, i.e., is in the correct linear space
func TestGenerateDealerSharesCommitmentsValid(t *testing.T) {
	testCases := []struct {
		n int
		d int
	}{
		{3, 1},
		{5, 2},
		{10, 3},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n
			d := tc.d

			// Generate params
			vssParams, err := vss.NewVSSParams(pedersen.GenerateParams(), n, d)
			require.NoError(err)

			vcParams, err := feldman.GenerateVCParams(tc.n * 2)
			require.NoError(err)

			// Generate secret and randomness
			r := curve25519.RandomScalar()
			s := curve25519.RandomScalar()

			// Generate comC
			_, comC, err := GenerateDealerSharesCommitments(vssParams, vcParams, s, r)
			require.NoError(err)

			// Verify validity of comC, that is they must be in the correct linear space
			valid, err := vss.VerifyCommitments(vssParams, comC)
			require.NoError(err)
			assert.True(valid)
		})
	}
}

func TestGenComZComZPrimeProofValidProof(t *testing.T) {
	testCases := []struct {
		n int
		d int
	}{
		{3, 1},
		{5, 2},
		{10, 3},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n
			d := tc.d

			// Generate sigmaRho and params
			vssParams, err := vss.NewVSSParams(pedersen.GenerateParams(), n, d)
			require.NoError(err)

			vcParams, err := feldman.GenerateVCParams(tc.n * 2)
			require.NoError(err)

			r := curve25519.RandomScalar()
			s := curve25519.RandomScalar()

			sigmaRho, _, err := GenerateDealerSharesCommitments(vssParams, vcParams, s, r)
			require.NoError(err)

			// Generate Z/Z'/proof
			comZ, comZPrime, proof, err := genComZComZPrimeProof(n, vcParams, sigmaRho)
			require.NoError(err)

			// Verify validity of the proof
			stmt := DblDLEqStatement{
				G:      vcParams.Bases[:n],
				H:      vcParams.Bases[n:],
				Z:      comZ,
				ZPrime: comZPrime,
			}
			err = DblDLEqVerify(stmt, proof)
			assert.NoError(err)
		})
	}
}

// TestGenComZComZPrimeProofValidComZ checks that comZ is valid, i.e., is in the correct linear space with
// the Persen commitment of (s,r)=(s_i,r_i)
func TestGenComZComZPrimeProofValidComZ(t *testing.T) {
	testCases := []struct {
		n int
		d int
	}{
		{3, 1},
		{5, 2},
		{10, 3},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n
			d := tc.d

			// Generate sigmaRho and params
			vssParams, err := vss.NewVSSParams(pedersen.GenerateParams(), n, d)
			require.NoError(err)

			vcParams, err := feldman.GenerateVCParams(tc.n * 2)
			require.NoError(err)

			r := curve25519.RandomScalar()
			s := curve25519.RandomScalar()

			sigmaRho, _, err := GenerateDealerSharesCommitments(vssParams, vcParams, s, r)
			require.NoError(err)

			// Generate Z/Z'/proof
			comZ, _, _, err := genComZComZPrimeProof(n, vcParams, sigmaRho)
			require.NoError(err)

			// Verify validity of comZ, that is they must be in the correct linear space
			// when prepended by the commitment of (s,r)
			comZ0, err := pedersen.GenerateCommitmentFixedR(vssParams.PedersenParams, s, r)
			require.NoError(err)

			allZ := []pedersen.Commitment{*comZ0}
			allZ = append(allZ, comZ...)

			valid, err := vss.VerifyCommitments(vssParams, allZ)
			require.NoError(err)
			assert.True(valid)
		})
	}
}
