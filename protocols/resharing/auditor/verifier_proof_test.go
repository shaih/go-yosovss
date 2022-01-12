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

func TestVPProveCorrect(t *testing.T) {
	testCases := []struct {
		n      int
		d      int
		j      int
		iFirst int // iFirst = first qualified dealer (assume that qualified dealers are a range)
		iLast  int // iLast = last qualified dealer
	}{
		{2, 1, 0, 0, 1},
		{10, 3, 1, 0, 9},
		{10, 3, 1, 1, 1},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n

			// Create a valid statement
			vcParams, sigma, comC, err := genVPInputs(tc.n, tc.d, tc.j)
			require.NoError(err)

			// Generate the proof
			vpcp, err := VPCommitAndProve(vcParams, sigma[tc.iFirst:(tc.iLast+1)])
			require.NoError(err)

			// Verify it
			for l := 0; l <= n; l++ {
				sigmaL := make([]curve25519.Scalar, n)
				for i := 0; i < n; i++ {
					sigmaL[i] = sigma[i][l]
				}
				err = VPVerify(*vcParams, l, comC[tc.iFirst:(tc.iLast+1)], vpcp, sigmaL[tc.iFirst:(tc.iLast+1)])
				assert.NoError(err)
			}
		})
	}
}

func TestVPProveIncorrect(t *testing.T) {
	testCases := []struct {
		n      int
		d      int
		j      int
		iFirst int // iFirst = first qualified dealer (assume that qualified dealers are a range)
		iLast  int // iLast = last qualified dealer
	}{
		{2, 1, 0, 0, 1},
		{10, 3, 1, 0, 9},
		{10, 3, 1, 1, 1},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n

			// Create a valid statement
			vcParams, sigma, comC, err := genVPInputs(tc.n, tc.d, tc.j)
			require.NoError(err)

			// Generate the proof
			vpcp, err := VPCommitAndProve(vcParams, sigma[tc.iFirst:(tc.iLast+1)])
			require.NoError(err)

			// Verify it
			for l := 0; l <= n; l++ {
				sigmaL := make([]curve25519.Scalar, n)
				for i := 0; i < n; i++ {
					sigmaL[i] = sigma[i][l]
				}

				// Make it incorrect by making one sigma invalid
				badSigmaL := make([]curve25519.Scalar, n)
				copy(badSigmaL, sigmaL)
				badSigmaL[tc.iFirst] = *curve25519.RandomScalar()
				err = VPVerify(*vcParams, l, comC[tc.iFirst:(tc.iLast+1)], vpcp, badSigmaL[tc.iFirst:(tc.iLast+1)])
				assert.Error(err)

				// Make it incorrect by making one of the commitment incorrect
				badComC := make([]curve25519.PointXY, n)
				copy(badComC, comC)
				badComC[tc.iLast] = *curve25519.RandomPointXY()
				err = VPVerify(*vcParams, l, badComC[tc.iFirst:(tc.iLast+1)], vpcp, sigmaL[tc.iFirst:(tc.iLast+1)])
				assert.Error(err)
			}
		})
	}
}

// genVPInputs generates a sigma / comC as received/used by a verified j
// j may be in [0,n-1]
// Using j=0 should be good enough
func genVPInputs(n, d, j int) (
	vcParams *feldman.VCParams,
	sigma [][]curve25519.Scalar, comC []feldman.VC, err error) {

	if j < 0 || j >= n {
		return nil, nil, nil, fmt.Errorf("j must be between 0 and n-1")
	}
	if d < 0 || d >= n {
		return nil, nil, nil, fmt.Errorf("d must be between 0 and n-1")
	}

	vcParams, err = feldman.GenerateVCParams(n)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error generating vcparams: %w", err)
	}

	vssParams, err := vss.NewVSSParams(pedersen.GenerateParams(), n, d)
	if err != nil {
		return nil, nil, nil, err
	}

	// allSigma[i][j][l] = sigma_{i+1,j+1,l+1}
	allSigma := make([][][]curve25519.Scalar, n)
	// allComC[i][j] = C_{i+1,j+1}
	allComC := make([][]feldman.VC, n)
	for i := 0; i < n; i++ {
		s := curve25519.RandomScalar()
		allSigma[i], allComC[i], err = GenerateDealerSharesCommitments(vssParams, vcParams, s)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// sigma[i][l]
	sigma = make([][]curve25519.Scalar, n)
	comC = make([]feldman.VC, n)
	for i := 0; i < n; i++ {
		comC[i] = allComC[i][j]
		sigma[i] = make([]curve25519.Scalar, n+1)
		copy(sigma[i], allSigma[i][j+1])
	}

	return vcParams, sigma, comC, nil
}
