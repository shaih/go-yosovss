package shamir

import (
	"fmt"

	"github.com/shaih/go-yosovss/primitives/curve25519"
)

// Share is composed of values used in Pedersen VSS to reconstruct a secret
type Share struct {
	Index       int
	IndexScalar curve25519.Scalar
	S           curve25519.Scalar
}

// Message is the value the dealer
type Message = curve25519.Scalar

// GenerateShares creates shares of t-of-n Shamir secret sharing for some secret m
func GenerateShares(m Message, t int, n int) (shares []Share, err error) {
	// The shares to be distributed to participants
	shares = make([]Share, n)

	f := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_{t-1} * x^{t-1} where a_0 = m and a_1,...,a_{t-1} are random

	f.Coefficients[0] = curve25519.Scalar(m)

	// Generate random values for remaining coefficients
	chacha20Key, err := curve25519.RandomChacha20Key()
	if err != nil {
		return nil, err
	}
	for i := 1; i < t; i++ {
		curve25519.RandomScalarChacha20C(&f.Coefficients[i], &chacha20Key, uint64(i))
	}

	// Perform Shamir secret sharing on the generated polynomials to construct shares
	for i := 1; i <= n; i++ {
		// The share of participant i is s_i = f(i)
		shares[i-1].Index = i
		curve25519.GetScalarC(&shares[i-1].IndexScalar, uint64(i))
		f.EvaluateC(&shares[i-1].S, &shares[i-1].IndexScalar)
	}

	return shares, nil
}

// Reconstruct takes in t shares and then does polynomial interpolation
// to obtain the original message
func Reconstruct(shares []Share) (*Message, error) {

	// Polynomial interpolation evaluated at 0
	sum := &curve25519.Scalar{}
	*sum = curve25519.ScalarZero
	for i := 0; i < len(shares); i++ {
		term := &curve25519.Scalar{}
		*term = shares[i].S
		for j := 0; j < len(shares); j++ {
			if i != j {
				denom, err := curve25519.InvertScalar(
					curve25519.SubScalar(&shares[j].IndexScalar, &shares[i].IndexScalar))
				if err != nil {
					return nil, fmt.Errorf("error in polynomial interpolation")
				}
				term = curve25519.MultScalar(term, curve25519.MultScalar(&shares[j].IndexScalar, denom))
			}
		}
		sum = curve25519.AddScalar(sum, term)
	}

	return (*Message)(sum), nil
}
