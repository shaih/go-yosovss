package auditor

import (
	"fmt"
	"testing"

	"github.com/shaih/go-yosovss/primitives/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDealerQualifiedValid(t *testing.T) {
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

			pub, prvs, _, _, _ := setupResharingSeq(t, tc.n, tc.d)
			vectorV, err := vss.GenerateVectorV(&pub.VSSParams)
			require.NoError(err)

			for i := 0; i < tc.n; i++ {
				msg, err := PerformDealing(pub, &prvs[i], &PartyDebugParams{})
				require.NoError(err)

				// check a valid dealer is qualified
				err = checkDealerQualified(pub, i, *msg, vectorV)
				assert.NoError(err, "error with dealer %d", i)
			}
		})
	}
}
