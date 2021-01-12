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

	assert.Equal(t, ScalarZero, AddScalar(x, negX), "Negation is correct")
	assert.Equal(t, ScalarOne, MultScalar(x, invX), "Inverse is correct")
}

func TestMultPointScalar(t *testing.T) {
	p := RandomPoint()
	n := RandomScalar()
	r1, err := MultPointScalar(p, n)
	if err != nil {
		log.Fatal(err)
	}

	r2, err := MultPointScalar(p, ScalarOne)
	if err != nil {
		log.Fatal(err)
	}

	assert.True(t, IsValidPoint(r1), "Point scalar multiplication is valid")
	assert.Equal(t, p, r2, "Point scalar multiplication with scalar 1")
}

func TestEncryption(t *testing.T) {
	pk, sk := GenerateKeys()
	m := Message([]byte{64, 136, 53, 44, 253, 57, 234, 186, 114, 18, 153, 65, 65, 192, 36,
		57, 161, 245, 97, 149, 79, 154, 111, 72, 195, 101, 225, 252, 115, 255, 141, 46, 101,
		117, 90, 158, 34, 143, 169, 134, 123, 204, 214, 189, 144, 87, 212, 255, 68, 245, 197,
		135, 130, 224, 14, 3, 122, 209, 108, 36, 103, 130, 107, 217, 170, 141, 236, 234, 223,
		222, 116, 182, 178, 119, 91, 193, 255, 248, 130, 162, 142, 255, 177, 46, 17, 11, 23,
		142, 30, 252, 192, 214, 106, 237, 225, 212, 145})
	c, err := Encrypt(pk, m)
	if err != nil {
		log.Fatal(err)
	}

	dec, err := Decrypt(pk, sk, c)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, m, dec, "Encryption is consistent")
}
