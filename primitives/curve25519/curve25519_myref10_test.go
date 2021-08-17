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

	y2incorrect, err := MultPointScalar(&BaseH, n)
	require.NoError(err)

	assert.NotEqual(y2incorrect, y1)
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

	y2incorrect, err := MultPointScalar(&BaseG, n)
	require.NoError(err)

	assert.NotEqual(y2incorrect, y1)
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

func TestDoubleMultBaseGHPointScalar(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	a := RandomScalar()
	b := RandomScalar()

	// Computation naive
	ag, err := MultBaseGPointScalar(a)
	require.NoError(err)
	bh, err := MultBaseHPointScalar(b)
	require.NoError(err)
	y1, err := AddPoint(ag, bh)
	require.NoError(err)

	// Computation with the fast function
	y2, err := DoubleMultBaseGHPointScalar(a, b)
	require.NoError(err)
	assert.Equal(*y1, *y2)
}

func TestDoubleMultBaseGHPointScalarZero(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	y, err := DoubleMultBaseGHPointScalar(&ScalarZero, &ScalarZero)
	require.NoError(err)
	assert.Equal(PointInfinity, *y)

	y, err = DoubleMultBaseGHPointScalar(&ScalarOne, &ScalarZero)
	require.NoError(err)
	assert.Equal(BaseG, *y)

	y, err = DoubleMultBaseGHPointScalar(&ScalarZero, &ScalarOne)
	require.NoError(err)
	assert.Equal(BaseH, *y)
}

func TestEvaluationAgainstNaive(t *testing.T) {
	assert := assert.New(t)

	degree := 5
	f := Polynomial{Coefficients: make([]Scalar, degree+1)}
	for i := 0; i <= degree; i++ {
		f.Coefficients[i] = *RandomScalar()
	}
	x := RandomScalar()

	y1 := f.EvaluateNaive(x)
	y2 := f.Evaluate(x)

	assert.Equal(*y1, *y2)
}
