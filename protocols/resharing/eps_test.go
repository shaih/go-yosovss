package resharing

import (
	"fmt"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconstructEpsKey(t *testing.T) {
	testCases := []struct {
		n int
		d int
	}{
		{11, 5},
		{2, 1},
		{21, 3},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("n=%d,d=%d", tc.n, tc.d), func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			n := tc.n
			d := tc.d

			epsKey, epsL, hashEps, err := GenerateAllEps(n, d)
			require.NoError(err)

			for k := 0; k < n; k++ {
				shares := make([]*curve25519.Scalar, n)
				for l := 0; l < n; l++ {
					shares[l] = &epsL[l].Eps[k]
				}

				// Check reconstruction with all shares
				reconsKey, err := ReconstructEpsKey(n, d, shares, hashEps[k])
				require.NoError(err)
				assert.Equal(epsKey[k], reconsKey,
					"reconstructed key match original key when reconstruction with all shares")

				// Check reconstruction with the last d+1 shares only
				for l := 0; l < n-(d+1); l++ {
					shares[l] = nil
				}
				reconsKey, err = ReconstructEpsKey(n, d, shares, hashEps[k])
				require.NoError(err)
				assert.Equal(epsKey[k], reconsKey,
					"reconstructed key match original key when reconstruction with d+1 shares")

				// Check reconstruction with some invalid shares
				for l := 0; l < n-(d+1); l++ {
					s := curve25519.GetScalar(42) // 42 is not the answer here :-) It's an invalid share
					shares[l] = s
				}
				reconsKey, err = ReconstructEpsKey(n, d, shares, hashEps[k])
				require.NoError(err)
				assert.Equal(epsKey[k], reconsKey,
					"reconstructed key match original key when reconstruction with d+1 shares")
			}
		})
	}

}
