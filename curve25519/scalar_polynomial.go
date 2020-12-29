package curve25519

// Polynomial is a represtation of a polynomial over Scalars
type Polynomial struct {
	Coefficients []Scalar
}

// Degree gets the degree of the polynomial
func (p *Polynomial) Degree() int {
	if len(p.Coefficients) == 0 {
		return 0
	}
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
