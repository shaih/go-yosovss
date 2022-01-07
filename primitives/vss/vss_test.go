package vss

import (
	"fmt"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

			// Checking that commitments are valid with randomized algorithm
			valid, err = VerifyCommitmentsRandomized(params, commitments)
			require.NoError(err)
			assert.True(valid, "honestly generated commitments are valid with randomized algorithm")

			// Checking that shares are valid
			for i := 0; i < tc.n; i++ {
				valid, err = VerifyShare(params, &shares[i], commitments)
				require.NoError(err)
				assert.Truef(valid, "share %d is valid", i)
			}

			// Checking that reconstruction works with the t first shares
			recS, err := Reconstruct(params, shares[0:tc.t], commitments)
			require.NoError(err)
			require.True(curve25519.ScalarEqual(s, recS), "reconstruction works with t first shares")

			// Checking that reconstruction works with all the shares
			recS, err = Reconstruct(params, shares[0:tc.t], commitments)
			require.NoError(err)
			require.True(curve25519.ScalarEqual(s, recS), "reconstruction works with all the shares")

			// Check that reconstruction works when making first share invalid
			if tc.t < tc.n {
				sharesWith0Invalid := make([]Share, tc.n)
				copy(sharesWith0Invalid, shares)
				// force first share to be invalid
				r := curve25519.AddScalar(&sharesWith0Invalid[0].R, &curve25519.ScalarOne)
				sharesWith0Invalid[0].R = *r

				recS, err = Reconstruct(params, sharesWith0Invalid, commitments)
				require.NoError(err)
				require.True(curve25519.ScalarEqual(s, recS), "reconstruction works with one incorrect share")
			}

			// Checking that verify commitments fail with first invalid commitment
			commitmentsWith0Invalid := make([]pedersen.Commitment, tc.n+1)
			copy(commitmentsWith0Invalid, commitments)
			c, err := curve25519.MultPointXYScalar(&commitmentsWith0Invalid[0], curve25519.GetScalar(2))
			commitmentsWith0Invalid[0] = *c
			require.NoError(err)
			valid, err = VerifyCommitments(params, commitmentsWith0Invalid)
			require.NoError(err)
			assert.False(valid, "incorrect commitments are invalid")

			// Checking that verify commitments fail with first invalid commitment with randomized algorithm
			valid, err = VerifyCommitmentsRandomized(params, commitmentsWith0Invalid)
			require.NoError(err)
			assert.False(valid, "incorrect commitments are invalid with randomized algorithm")

			// Checking that verify commitments fail with first invalid commitment
			commitmentsWithLastInvalid := make([]pedersen.Commitment, tc.n+1)
			copy(commitmentsWithLastInvalid, commitments)
			c, err = curve25519.MultPointXYScalar(&commitmentsWithLastInvalid[tc.n-1], curve25519.GetScalar(3))
			commitmentsWithLastInvalid[tc.n-1] = *c
			require.NoError(err)
			valid, err = VerifyCommitments(params, commitmentsWithLastInvalid)
			require.NoError(err)
			assert.False(valid, "incorrect commitments are invalid")

			// Checking that verify commitments fail with first invalid commitment with randomized algorithm
			valid, err = VerifyCommitmentsRandomized(params, commitmentsWithLastInvalid)
			require.NoError(err)
			assert.False(valid, "incorrect commitments are invalid with randomized algorithm")
		})
	}
}

// The functions below benchmark each step of the VSS verification

func BenchmarkVerifyCommitmentsStep1GenerateUVector(b *testing.B) {
	testCases := []struct {
		n int
		d int
	}{
		{2*32 + 1, 32},
		{2*64 + 1, 64},
		{2*128 + 1, 128},
		{2*256 + 1, 256},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("n=%d,d=%d", tc.n, tc.d), func(b *testing.B) {
			n := tc.n
			d := tc.d

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Generate a random vector u
				uVector := curve25519.NewScalarMatrix(n-d, 1)
				for i := 0; i < n-d; i++ {
					uVector.Set(i, 0, curve25519.RandomScalar())
				}
			}
		})
	}
}

func BenchmarkVerifyCommitmentsStep2MatrixMult(b *testing.B) {
	testCases := []struct {
		n int
		d int
	}{
		{2*32 + 1, 32},
		{2*64 + 1, 64},
		{2*128 + 1, 128},
		{2*256 + 1, 256},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("n=%d,d=%d", tc.n, tc.d), func(b *testing.B) {
			n := tc.n
			d := tc.d

			params, err := NewVSSParams(pedersen.GenerateParams(), n, d)
			if err != nil {
				b.Fatal(err)
			}

			// Generate a random vector u
			uVector := curve25519.NewScalarMatrix(n-d, 1)
			for i := 0; i < n-d; i++ {
				uVector.Set(i, 0, curve25519.RandomScalar())
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Multiply the parity matrix by the vector u to get a random vector v in the image of the parity matrix
				_, err = curve25519.ScalarMatrixMul(&params.ParityMatrix, uVector)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyCommitmentsStep3PointScalarMult(b *testing.B) {
	testCases := []struct {
		n int
		d int
	}{
		{2*32 + 1, 32},
		{2*64 + 1, 64},
		{2*128 + 1, 128},
		{2*256 + 1, 256},
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("n=%d,d=%d", tc.n, tc.d), func(b *testing.B) {
			n := tc.n

			comVector := curve25519.NewPointMatrix(1, n+1)
			vVector := curve25519.NewScalarMatrix(n+1, 1)
			for i := 0; i <= n; i++ {
				comVector.Set(0, i, curve25519.RandomPoint())
				vVector.Set(i, 0, curve25519.RandomScalar())
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Multiply comVector by v
				_, err := curve25519.PointMatrixScalarMatrixMul(comVector, vVector)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
