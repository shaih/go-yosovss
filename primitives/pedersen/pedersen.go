package pedersen

import (
	"fmt"

	"github.com/shaih/go-yosovss/primitives/curve25519"
)

// Params consists of two group elements g and h such that the
// commitment is of the form g^m * h^r
type Params struct {
}

// Message is the value the committer is committing to
type Message = curve25519.Scalar

// Commitment consists of elliptic curve point that serves as a
// commitment to a message
type Commitment = curve25519.PointXY

// Decommitment is the random value r used in a Pedersen commitment
type Decommitment = curve25519.Scalar

// GenerateParams now does nothing
// In the past, it generated the two basis G and H
func GenerateParams() *Params {
	//g := curve25519.RandomPoint()
	//h := curve25519.RandomPoint()
	//
	//for curve25519.PointEqual(g, h) {
	//	h = curve25519.RandomPoint()
	//}
	//
	//return &Params{
	//	G: g,
	//	H: h,
	//}
	return &Params{}
}

// GenerateCommitment creates a commitment for some value m
func GenerateCommitment(params *Params, m *Message) (*Commitment, *Decommitment, error) {

	r := curve25519.RandomScalar()

	c, err := curve25519.DoubleMultBaseGHPointXYScalar(m, r) // Compute g^m * h^r
	if err != nil {
		return nil, nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	return c, r, nil
}

// GenerateCommitmentFixedR creates a commitment for some value m with a fixed decommitment r
func GenerateCommitmentFixedR(params *Params, m *Message, r *Decommitment) (*Commitment, error) {

	c, err := curve25519.DoubleMultBaseGHPointXYScalar(m, r) // Compute g^m * h^r
	if err != nil {
		return nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	return c, nil
}

// VerifyCommitment checks if a commitment was for some message m under the
// decommitment r
func VerifyCommitment(params *Params, commitment *Commitment, m *Message, r *Decommitment) (bool, error) {

	c, err := curve25519.DoubleMultBaseGHPointXYScalar(m, r) // Compute g^m * h^r
	if err != nil {
		return false, fmt.Errorf("verification failed: %v", err)
	}

	return curve25519.PointXYEqual(commitment, c), nil
}
