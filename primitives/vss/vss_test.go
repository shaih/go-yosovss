package vss

import (
	"fmt"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVSS(t *testing.T) {
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

			params, err := NewVSSParams(pedersen.GenerateParams(), tc.n, tc.t-1)
			require.NoError(err)

			s := curve25519.GetScalar(42)
			r := curve25519.RandomScalar()

			shares, commitments, err := FixedRShare(params, s, r)
			require.NoError(err)

			// Checking that commitments are valid
			valid, err := VerifyCommitments(params, commitments)
			require.NoError(err)
			assert.True(valid, "honestly generated commitments are valid")

			// Checking that shares are valid
			for i := 0; i < tc.n; i++ {
				valid, err = VerifyShare(params, &shares[i], commitments)
				require.NoError(err)
				assert.Truef(valid, "share %d is valid", i)
			}

			// Checking that reconstruction works with the t first shares
			recS, err := Reconstruct(params, shares[0:tc.t], commitments)
			require.NoError(err)
			require.True(curve25519.ScalarEqual(s, *recS), "reconstruction works with t first shares")

			// Checking that reconstruction works with all the shares
			recS, err = Reconstruct(params, shares[0:tc.t], commitments)
			require.NoError(err)
			require.True(curve25519.ScalarEqual(s, *recS), "reconstruction works with all the shares")

			// Check that reconstruction works when making first share invalid
			if tc.t < tc.n {
				sharesWith0Invalid := make([]Share, tc.n)
				copy(sharesWith0Invalid, shares)
				// force first share to be invalid
				sharesWith0Invalid[0].R = curve25519.AddScalar(sharesWith0Invalid[0].R, curve25519.ScalarOne)

				recS, err = Reconstruct(params, sharesWith0Invalid, commitments)
				require.NoError(err)
				require.True(curve25519.ScalarEqual(s, *recS), "reconstruction works with one incorrect share")
			}

			// Checking that verify commitments fail with first invalid commitment
			commitmentsWith0Invalid := make([]pedersen.Commitment, tc.n+1)
			copy(commitmentsWith0Invalid, commitments)
			valid, err = VerifyCommitments(params, commitments)
			require.NoError(err)
			assert.True(valid, "incorrect commitments are invalid")
		})
	}
}
