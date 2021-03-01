package curve25519

import "fmt"

// Polynomial is a representation of a polynomial over Scalars
type Polynomial struct {
	Coefficients []Scalar
}

// Degree gets the degree of the polynomial
// The degree of the zero polynomial is -1
func (p *Polynomial) Degree() int {
	i := len(p.Coefficients) - 1
	for ; i > 0 && IsEqualScalar(p.Coefficients[i], ScalarZero); i-- {
	}
	return i
}

// Evaluate evaluates the polynomial p at a point x
func (p *Polynomial) Evaluate(x Scalar) Scalar {
	degree := p.Degree()
	evaluation := p.Coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		evaluation = MultScalar(evaluation, x)
		evaluation = AddScalar(evaluation, p.Coefficients[i])
	}
	return evaluation
}

// LagrangeCoeffs takes in a list of coordinates and the evaluation coordinate and returns the Lagrange coefficients
// lambda_i derived from those points
func LagrangeCoeffs(coords []Scalar, x Scalar) ([]Scalar, error) {
	lambdas := make([]Scalar, len(coords))
	for i := 0; i < len(coords); i++ {
		num := ScalarOne
		denom := ScalarOne
		for j := 0; j < len(coords); j++ {
			if i != j {
				num = MultScalar(num, SubScalar(x, coords[j]))
				denom = MultScalar(denom, SubScalar(coords[i], coords[j]))
			}
		}
		reciprocal, err := InvertScalar(denom)
		if err != nil {
			return nil, fmt.Errorf("unable to invert denominator for term %d: %v", i, err)
		}
		lambdas[i] = MultScalar(num, reciprocal)
	}
	return lambdas, nil
}
