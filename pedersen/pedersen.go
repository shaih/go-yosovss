package pedersen

import (
	"fmt"

	"github.com/shaih/go-yosovss/curve25519"
)

// Message is the value the commiter is committing to
type Message curve25519.Scalar

// Decommitment is the random value r used
type Decommitment curve25519.Scalar

// Commitment consists of two group elements g and h such that the
// commitment is of the form g^m * h^r
type Commitment struct {
	G          curve25519.Point
	H          curve25519.Point
	Commitment curve25519.Point
}

// GenerateCommitment creates a commitment for some value m
func GenerateCommitment(m Message) (*Commitment, *Decommitment, error) {
	g := curve25519.RandomPoint()
	h := curve25519.RandomPoint()

	for curve25519.IsEqualPoint(g, h) {
		h = curve25519.RandomPoint()
	}

	r := curve25519.RandomScalar()

	gm, err := curve25519.MultPointScalar(g, curve25519.Scalar(m)) // Compute g^m
	if err != nil {
		return nil, nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	hr, err := curve25519.MultPointScalar(h, r) // Compute h^r
	if err != nil {
		return nil, nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	c, err := curve25519.AddPoint(gm, hr) // Compute g^m * h^r
	if err != nil {
		return nil, nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	decommitment := Decommitment(r)
	return &Commitment{
		G:          g,
		H:          h,
		Commitment: c,
	}, &decommitment, nil
}

// VerifyCommitment checks if a commitment was for some message m under the
// decommitment r
func VerifyCommitment(commitment *Commitment, m Message, r *Decommitment) (bool, error) {
	gm, err := curve25519.MultPointScalar(commitment.G, curve25519.Scalar(m)) // Compute g^m
	if err != nil {
		return false, fmt.Errorf("verification failed: %v", err)
	}

	hr, err := curve25519.MultPointScalar(commitment.H, curve25519.Scalar(*r)) // Compute h^r
	if err != nil {
		return false, fmt.Errorf("verification failed: %v", err)
	}

	c, err := curve25519.AddPoint(gm, hr) // Compute g^m * h^r
	if err != nil {
		return false, fmt.Errorf("verification failed: %v", err)
	}

	return curve25519.IsEqualPoint(curve25519.Point(commitment.Commitment), c), nil
}
