package curve25519

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidPoint(t *testing.T) {
	p := RandomPoint()
	assert.True(t, IsValidPoint(p), "Random point is valid")

	var q Point
	assert.False(t, IsValidPoint(q), "Zero is not valid")
}

func TestIsEqualPoint(t *testing.T) {
	p := RandomPoint()
	q := p

	r, err := AddPoint(p, q)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, IsEqualPoint(p, q), "Point equality for equal values")
	assert.False(t, IsEqualPoint(p, r), "Point equality for different values")
}

func TestIsEqualScalar(t *testing.T) {
	x := RandomScalar()
	y := x
	z := RandomScalar()

	assert.True(t, IsEqualScalar(x, y), "Scalar equality for equal values")
	assert.False(t, IsEqualScalar(x, z), "Scalar equality for different values")
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

	var zero [32]byte
	one := [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	assert.Equal(t, Scalar(zero), AddScalar(x, negX), "Negation is correct")
	assert.Equal(t, Scalar(one), MultScalar(x, invX), "Inverse is correct")
}

func TestMultPointScalar(t *testing.T) {
	p := RandomPoint()
	n := RandomScalar()
	r, err := MultPointScalar(p, n)
	if err != nil {
		log.Fatal(err)
	}

	assert.True(t, IsValidPoint(r), "Point scalar multiplication is valid")
}
