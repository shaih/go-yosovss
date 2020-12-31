package curve25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDegree(t *testing.T) {
	var p Polynomial
	assert.Equal(t, -1, p.Degree())
	p.Coefficients = []Scalar{ScalarZero}
	assert.Equal(t, 0, p.Degree())
	p.Coefficients = []Scalar{ScalarOne}
	assert.Equal(t, 0, p.Degree())
	p.Coefficients = []Scalar{ScalarOne, ScalarOne, ScalarZero}
	assert.Equal(t, 1, p.Degree())
	p.Coefficients = []Scalar{ScalarOne, ScalarOne, ScalarOne, ScalarOne}
	assert.Equal(t, 3, p.Degree())
}

func TestEvaluation(t *testing.T) {
	var p Polynomial
	p.Coefficients = []Scalar{ScalarZero}
	assert.Equal(t, 0, p.Degree())
	p.Coefficients = []Scalar{ScalarOne}
	assert.Equal(t, 0, p.Degree())
	p.Coefficients = []Scalar{ScalarOne, ScalarOne, ScalarZero}
	assert.Equal(t, 1, p.Degree())
	p.Coefficients = []Scalar{ScalarOne, ScalarOne, ScalarOne, ScalarOne}
	assert.Equal(t, 3, p.Degree())
}
