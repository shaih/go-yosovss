package curve25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultBaseGPointScalar(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	y1, err := MultBaseGPointScalar(GetScalar(0))
	require.NoError(err)
	assert.Equal(PointInfinity, *y1)

	n := RandomScalar()

	y1, err = MultBaseGPointScalar(n)
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

func TestAddPointInfinity(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	p := PointInfinity
	q := PointInfinity
	r, err := AddPoint(&p, &q)
	require.NoError(err)
	assert.Equal(PointInfinity, *r)
}

func TestAddPoints(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	p := RandomPoint()

	r, err := AddPoints([]Point{PointInfinity})
	require.NoError(err)
	assert.Equal(PointInfinity, *r)

	r, err = AddPoints([]Point{PointInfinity, PointInfinity, PointInfinity})
	require.NoError(err)
	assert.Equal(PointInfinity, *r)

	r, err = AddPoints([]Point{PointInfinity, *p, PointInfinity})
	require.NoError(err)
	assert.Equal(*p, *r)

	r, err = AddPoints([]Point{PointInfinity, *p, *p, *p, PointInfinity, *p})
	require.NoError(err)
	r2, err := MultPointScalar(p, GetScalar(4))
	require.NoError(err)
	assert.Equal(*r2, *r)
}
