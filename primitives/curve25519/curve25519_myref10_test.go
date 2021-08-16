package curve25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultBaseGPointScalar(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	n := RandomScalar()

	y1, err := MultBaseGPointScalar(n)
	require.NoError(err)
	y2, err := MultPointScalar(&BaseG, n)
	require.NoError(err)

	assert.Equal(y2, y1)

	// FIXME: disabled because currently using same base
	//y2incorrect, err := MultPointScalar(&BaseH, n)
	//require.NoError(err)
	//
	//assert.NotEqual(y2incorrect, y1)
}

func TestMultBaseHPointScalar1(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	n := GetScalar(1)
	y1, err := MultBaseHPointScalar(n)
	require.NoError(err)

	assert.Equal(&BaseH, y1)
}

func TestMultBaseHPointScalar(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	n := RandomScalar()

	y1, err := MultBaseHPointScalar(n)
	require.NoError(err)
	y2, err := MultPointScalar(&BaseH, n)
	require.NoError(err)

	assert.Equal(y2, y1)

	// FIXME: disabled because currently using same base
	//y2incorrect, err := MultPointScalar(&BaseG, n)
	//require.NoError(err)
	//
	//assert.NotEqual(y2incorrect, y1)
}
