package curve25519

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidPoint(t *testing.T) {
	p := RandomPoint()
	assert.True(t, IsValidPoint(p), "Random point is valid")

	var q Point
	assert.False(t, IsValidPoint(&q), "Zero is not valid")
}

func TestGetScalar(t *testing.T) {
	assert.Equal(
		t,
		Scalar([32]byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		*GetScalar(5),
		"Single byte Scalar is correct",
	)

	assert.Equal(
		t,
		Scalar([32]byte{255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		*GetScalar(4294967295), // 2^32 - 1
		"Multiple byte Scalar is correct",
	)
}

func TestIsEqualPoint(t *testing.T) {
	p := RandomPoint()
	q := p
	q2 := &Point{}
	*q2 = *p

	r, err := AddPoint(p, q)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, PointEqual(p, q), "Point equality for equal values and pointers")
	assert.True(t, PointEqual(p, q2), "Point equality for equal values but not pointers")
	assert.False(t, PointEqual(p, r), "Point equality for different values")
}

func TestIsEqualScalar(t *testing.T) {
	x := RandomScalar()
	y := x
	z := RandomScalar()

	assert.True(t, ScalarEqual(x, y), "Scalar equality for equal values")
	assert.False(t, ScalarEqual(x, z), "Scalar equality for different values")
}

func TestAddPoint(t *testing.T) {
	p := RandomPoint()
	q := RandomPoint()

	r, err := AddPoint(p, q)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, IsValidPoint(r), "Point addition is valid")
}
func TestSubPoint(t *testing.T) {
	p := RandomPoint()
	q := RandomPoint()

	r, err := SubPoint(p, q)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, IsValidPoint(r), "Point subtraction is valid")
}

func TestScalarOperations(t *testing.T) {
	x := RandomScalar()
	negX := NegateScalar(x)
	invX, err := InvertScalar(x)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, ScalarZero, *AddScalar(x, negX), "Negation is correct")
	assert.Equal(t, ScalarOne, *MultScalar(x, invX), "Inverse is correct")
}

func TestMultPointScalar(t *testing.T) {
	p := RandomPoint()
	n := RandomScalar()
	r1, err := MultPointScalar(p, n)
	if err != nil {
		log.Fatal(err)
	}

	r2, err := MultPointScalar(p, &ScalarOne)
	if err != nil {
		log.Fatal(err)
	}

	assert.True(t, IsValidPoint(r1), "Point scalar multiplication is valid")
	assert.Equal(t, p, r2, "Point scalar multiplication with scalar 1")
}

//func TestMultPointScalarZero(t *testing.T) {
//	p := RandomPoint()
//	r1, err := MultPointScalar(p, GetScalar(0))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	assert.True(t, IsValidPoint(r1), "Point scalar multiplication is valid")
//}

func TestPointInfinity(t *testing.T) {
	//assert.True(t, IsValidPoint(PointInfinity), "Infinity point is valid")
	p := RandomPoint()
	r, err := AddPoint(p, &PointInfinity)
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, p, r, "Add by infinity")

	negP, err := MultPointScalar(p, NegateScalar(GetScalar(1)))
	if err != nil {
		log.Fatal(err)
	}

	r1, err := AddPoint(p, negP)
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, PointInfinity, *r1, "p + (-p) = infinity")
	//
	//r2, err := MultPointScalar(p, GetScalar(0))
	//if err != nil {
	//	log.Fatal(err)
	//}
	//assert.Equal(t, PointInfinity, r2, "0*p = infinity")

}

func TestAddPointsNaive(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	p := RandomPoint()

	r, err := AddPointsNaive([]Point{PointInfinity, PointInfinity, PointInfinity})
	require.NoError(err)
	assert.Equal(PointInfinity, *r)

	r, err = AddPointsNaive([]Point{PointInfinity, *p, PointInfinity})
	require.NoError(err)
	assert.Equal(*p, *r)

	r, err = AddPointsNaive([]Point{PointInfinity, *p, *p, *p, PointInfinity, *p})
	require.NoError(err)
	r2, err := MultPointScalar(p, GetScalar(4))
	require.NoError(err)
	assert.Equal(*r2, *r)

}
