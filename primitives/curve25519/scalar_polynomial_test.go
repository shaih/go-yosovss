package curve25519

import (
	"log"
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

func TestLagrangeCoeffs(t *testing.T) {
	coords := []Scalar{GetScalar(6), GetScalar(8), GetScalar(12)}

	// Expected Lagrange coefficients are the vector (16, -27, 12)
	expectedLambdas := []Scalar{GetScalar(16), SubScalar(ScalarZero, GetScalar(27)), GetScalar(12)}
	lambdas, err := LagrangeCoeffs(coords, GetScalar(24))
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, expectedLambdas, lambdas)

}
