package curve25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsOnCurve(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsOnCurveXY(&PointXYInfinity))

	p := RandomPointXY()
	assert.True(IsOnCurveXY(p))

	p[0]++
	assert.False(IsOnCurveXY(p))
}

func TestAddSubPointsXY(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	r, err := AddPointXY(&PointXYInfinity, &PointXYInfinity)
	require.NoError(err)
	assert.Equal(&PointXYInfinity, r)

	p := RandomPointXY()
	q := RandomPointXY()

	subPP, err := SubPointXY(p, p)
	require.NoError(err)
	assert.Equal(&PointXYInfinity, subPP)

	addPQ, err := AddPointXY(p, q)
	require.NoError(err)
	assert.True(IsOnCurveXY(addPQ))

	addPPsubQ, err := SubPointXY(addPQ, q)
	require.NoError(err)
	assert.Equal(p, addPPsubQ)
}

func TestAddPointXYAgainstNonCompressed(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	// Test against the non-compressed version

	p := RandomPoint()
	pxy, err := PointToPointXY(p)
	require.NoError(err)

	q := RandomPoint()
	qxy, err := PointToPointXY(q)
	require.NoError(err)

	r1, err := AddPoint(p, q)
	require.NoError(err)

	r2xy, err := AddPointXY(pxy, qxy)
	require.NoError(err)

	r1xy, err := PointToPointXY(r1)
	require.NoError(err)

	assert.Equal(r1xy, r2xy)
}

func TestSubPointXYAgainstNonCompressed(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	// Test against the non-compressed version

	p := RandomPoint()
	pxy, err := PointToPointXY(p)
	require.NoError(err)

	q := RandomPoint()
	qxy, err := PointToPointXY(q)
	require.NoError(err)

	r1, err := SubPoint(p, q)
	require.NoError(err)

	r2xy, err := SubPointXY(pxy, qxy)
	require.NoError(err)

	r1xy, err := PointToPointXY(r1)
	require.NoError(err)

	assert.Equal(r1xy, r2xy)
}

func TestMultPointXYScalarAgainstNonCompressed(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	// Test against the non-compressed version

	p := RandomPoint()
	pxy, err := PointToPointXY(p)
	require.NoError(err)
	n := RandomScalar()

	r1, err := MultPointScalar(p, n)
	require.NoError(err)

	r2xy, err := MultPointXYScalar(pxy, n)
	require.NoError(err)

	r1xy, err := PointToPointXY(r1)
	require.NoError(err)

	assert.Equal(r1xy, r2xy)
}

func TestDoubleMultBaseGHPointXYScalarZero(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	y, err := DoubleMultBaseGHPointXYScalar(&ScalarZero, &ScalarZero)
	require.NoError(err)
	assert.Equal(PointXYInfinity, *y)

	y, err = DoubleMultBaseGHPointXYScalar(&ScalarOne, &ScalarZero)
	require.NoError(err)
	assert.Equal(BaseXYG, *y)

	y, err = DoubleMultBaseGHPointXYScalar(&ScalarZero, &ScalarOne)
	require.NoError(err)
	assert.Equal(BaseXYH, *y)
}

func TestMultBaseGPointXYScalar(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	y1, err := MultBaseGPointXYScalar(GetScalar(0))
	require.NoError(err)
	assert.Equal(PointXYInfinity, *y1)

	n := RandomScalar()

	y1, err = MultBaseGPointXYScalar(n)
	require.NoError(err)
	y2, err := MultPointXYScalar(&BaseXYG, n)
	require.NoError(err)

	assert.Equal(y2, y1)

	y2incorrect, err := MultPointXYScalar(&BaseXYH, n)
	require.NoError(err)

	assert.NotEqual(y2incorrect, y1)
}

func TestMultBaseHPointXYScalar1(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	n := GetScalar(1)
	y1, err := MultBaseHPointXYScalar(n)
	require.NoError(err)

	assert.Equal(&BaseXYH, y1)
}

func TestMultBaseHPoinXYScalar(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	n := RandomScalar()

	y1, err := MultBaseHPointXYScalar(n)
	require.NoError(err)
	y2, err := MultPointXYScalar(&BaseXYH, n)
	require.NoError(err)

	assert.Equal(y2, y1)

	y2incorrect, err := MultPointXYScalar(&BaseXYG, n)
	require.NoError(err)

	assert.NotEqual(y2incorrect, y1)
}

func TestAddPointsXY(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	p := RandomPointXY()

	r, err := AddPointsXY([]PointXY{PointXYInfinity})
	require.NoError(err)
	assert.Equal(PointXYInfinity, *r)

	r, err = AddPointsXY([]PointXY{PointXYInfinity, PointXYInfinity, PointXYInfinity})
	require.NoError(err)
	assert.Equal(PointXYInfinity, *r)

	r, err = AddPointsXY([]PointXY{PointXYInfinity, *p, PointXYInfinity})
	require.NoError(err)
	assert.Equal(*p, *r)

	r, err = AddPointsXY([]PointXY{PointXYInfinity, *p, *p, *p, PointXYInfinity, *p})
	require.NoError(err)
	r2, err := MultPointXYScalar(p, GetScalar(4))
	require.NoError(err)
	assert.Equal(*r2, *r)
}

func TestAddPointsXYCheckOnCurve(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	p := RandomPointXY()

	r, err := AddPointsXYCheckOnCurve([]PointXY{PointXYInfinity})
	require.NoError(err)
	assert.Equal(PointXYInfinity, *r)

	r, err = AddPointsXYCheckOnCurve([]PointXY{PointXYInfinity, PointXYInfinity, PointXYInfinity})
	require.NoError(err)
	assert.Equal(PointXYInfinity, *r)

	r, err = AddPointsXYCheckOnCurve([]PointXY{PointXYInfinity, *p, PointXYInfinity})
	require.NoError(err)
	assert.Equal(*p, *r)

	r, err = AddPointsXYCheckOnCurve([]PointXY{PointXYInfinity, *p, *p, *p, PointXYInfinity, *p})
	require.NoError(err)
	r2, err := MultPointXYScalar(p, GetScalar(4))
	require.NoError(err)
	assert.Equal(*r2, *r)

	// make p incorrect and test it is detected
	p[0]++
	r, err = AddPointsXYCheckOnCurve([]PointXY{PointXYInfinity, *p, *p, *p, PointXYInfinity, *p})
	assert.Nil(r)
	assert.NotNil(err)
}

func TestAddPointsXYNaive(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	p := RandomPointXY()

	r, err := AddPointsXYNaive([]PointXY{PointXYInfinity})
	require.NoError(err)
	assert.Equal(PointXYInfinity, *r)

	r, err = AddPointsXYNaive([]PointXY{PointXYInfinity, PointXYInfinity, PointXYInfinity})
	require.NoError(err)
	assert.Equal(PointXYInfinity, *r)

	r, err = AddPointsXYNaive([]PointXY{PointXYInfinity, *p, PointXYInfinity})
	require.NoError(err)
	assert.Equal(*p, *r)

	r, err = AddPointsXYNaive([]PointXY{PointXYInfinity, *p, *p, *p, PointXYInfinity, *p})
	require.NoError(err)
	r2, err := MultPointXYScalar(p, GetScalar(4))
	require.NoError(err)
	assert.Equal(*r2, *r)
}
