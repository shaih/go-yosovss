package feldman

import (
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateVectorCommitmentParamsBasic(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	vcp, err := GenerateVCParams(10)
	require.NoError(err)

	assert.Equal(vcp.N, 10)
	assert.Equal(len(vcp.Bases), vcp.N)
}

func TestGenerateVectorCommitmentParamsValidBases(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	n := 10
	vcp, err := GenerateVCParams(n)
	require.NoError(err)

	for i := 0; i < n; i++ {
		assert.True(curve25519.IsOnCurveXY(&vcp.Bases[i]))
		p, err := curve25519.PointXYToPoint(&vcp.Bases[i])
		require.NoError(err)
		assert.True(curve25519.IsValidPoint(p))
	}
}

func TestGenerateVectorCommitmentParamsDistinctBases(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	n := 10
	vcp, err := GenerateVCParams(n)
	require.NoError(err)

	for i := 0; i < n; i++ {
		assert.NotEqual(vcp.Bases[i], &curve25519.BaseXYG)
		assert.NotEqual(vcp.Bases[i], &curve25519.BaseXYH)
		assert.NotEqual(vcp.Bases[i], &curve25519.PointXYInfinity)

		for j := i + 1; j < n; j++ {
			assert.NotEqual(vcp.Bases[i], vcp.Bases[j])
		}
	}
}
