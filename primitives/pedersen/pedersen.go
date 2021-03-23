package pedersen

import (
	"fmt"

	"github.com/shaih/go-yosovss/primitives/curve25519"
)

// Params consists of two group elements g and h such that the
// commitment is of the form g^m * h^r
type Params struct {
	G curve25519.Point
	H curve25519.Point
}

// Share is composed of values used in Pedersen VSS to reconstruct a secret
type Share struct {
	Index       int
	IndexScalar curve25519.Scalar
	S           curve25519.Scalar
	R           curve25519.Scalar
}

// Message is the value the committer is committing to
type Message curve25519.Scalar

// Commitment consists of elliptic curve point that serves as a
// commitment to a message
type Commitment curve25519.Point

// Decommitment is the random value r used
type Decommitment curve25519.Scalar

// GenerateParams picks two random group elements for generating commitments
func GenerateParams() *Params {
	g := curve25519.RandomPoint()
	h := curve25519.RandomPoint()

	for curve25519.IsEqualPoint(g, h) {
		h = curve25519.RandomPoint()
	}

	return &Params{
		G: g,
		H: h,
	}
}

// GenerateCommitment creates a commitment for some value m
func GenerateCommitment(params *Params, m Message) (*Commitment, *Decommitment, error) {

	r := curve25519.RandomScalar()

	gm, err := curve25519.MultPointScalar(params.G, curve25519.Scalar(m)) // Compute g^m
	if err != nil {
		return nil, nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	hr, err := curve25519.MultPointScalar(params.H, r) // Compute h^r
	if err != nil {
		return nil, nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	c, err := curve25519.AddPoint(gm, hr) // Compute g^m * h^r
	if err != nil {
		return nil, nil, fmt.Errorf("commitment generation failed: %v", err)
	}

	commitment := Commitment(c)
	decommitment := Decommitment(r)

	return &commitment, &decommitment, nil
}

// VerifyCommitment checks if a commitment was for some message m under the
// decommitment r
func VerifyCommitment(params *Params, commitment *Commitment, m Message, r *Decommitment) (bool, error) {
	gm, err := curve25519.MultPointScalar(params.G, curve25519.Scalar(m)) // Compute g^m
	if err != nil {
		return false, fmt.Errorf("verification failed: %v", err)
	}

	hr, err := curve25519.MultPointScalar(params.H, curve25519.Scalar(*r)) // Compute h^r
	if err != nil {
		return false, fmt.Errorf("verification failed: %v", err)
	}

	c, err := curve25519.AddPoint(gm, hr) // Compute g^m * h^r
	if err != nil {
		return false, fmt.Errorf("verification failed: %v", err)
	}

	return curve25519.IsEqualPoint(curve25519.Point(*commitment), c), nil
}

// VSSShare performs the intial dealer's step for a Pedersen VSS on the message m
// for t-of-n reconstruction.
func VSSShare(params *Params, m Message, t int, n int) ([]Share, []Commitment, error) {
	if t < 1 || n < 1 || t > n {
		return nil, nil, fmt.Errorf("invalid share generation parameters")
	}

	// The shares to be distributed to participants
	var shares []Share

	// The commitments to the coefficient of polynomials used to verify
	// correctness of shares
	var verifications []Commitment

	f := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_{t-1} * x^{t-1} where a_0 = m and a_1,...,a_{t-1} are random
	g := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // g(x) = b_0 + b_1 * x + b_2 * x^2 + ... + b_{t-1]} * x^{t-1} where b_0,...,b_{t-1} are random

	// Get commitment to the secret
	commitment, decommitment, err := GenerateCommitment(params, m)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating message commitment")
	}
	f.Coefficients[0] = curve25519.Scalar(m)
	g.Coefficients[0] = curve25519.Scalar(*decommitment)

	verifications = append(verifications, *commitment)

	// Generate random values for remaining coefficients
	for i := 1; i < t; i++ {
		f.Coefficients[i] = curve25519.RandomScalar()
		// Get commitment the random polynomial coefficients
		commitment, decommitment, err = GenerateCommitment(params, Message(f.Coefficients[i]))
		if err != nil {
			return nil, nil, fmt.Errorf("error generating commitment")
		}
		g.Coefficients[i] = curve25519.Scalar(*decommitment)

		// verification of ith coefficient is g^a_i * h^b_i
		verifications = append(verifications, *commitment)
	}

	// Perform Shamir secret sharing on the generated polynomials to construct shares
	evalPoint := curve25519.ScalarZero
	for i := 1; i <= n; i++ {
		// NOTE: Expensive step, consider changing in the future
		evalPoint = curve25519.AddScalar(evalPoint, curve25519.ScalarOne)

		shares = append(shares, Share{
			Index:       i,
			IndexScalar: evalPoint,
			S:           f.Evaluate(evalPoint),
			R:           g.Evaluate(evalPoint),
		}) // The share of participant i is (s_i, r_i) = (f(i), g(i))
	}

	return shares, verifications, nil
}

// VSSVerify performs verification of a received share with the broadcasted
// verification.
func VSSVerify(params *Params, share Share, verifications []Commitment) (bool, error) {
	t := len(verifications)
	gs, err := curve25519.MultPointScalar(params.G, share.S)
	if err != nil {
		return false, fmt.Errorf("error in evaluating share")
	}

	hr, err := curve25519.MultPointScalar(params.H, share.R)
	if err != nil {
		return false, fmt.Errorf("error in evaluating share")
	}

	shareResult, err := curve25519.AddPoint(gs, hr) // Compute g^{s_i} * h^{r_i}
	if err != nil {
		return false, fmt.Errorf("error in evaluating share")
	}

	// Compute \prod_{j=0}^{t-1}E_j^{i^j} where E_j is the jth entry in the verification vector
	verificationResult := curve25519.Point(verifications[t-1])
	for j := t - 2; j >= 0; j-- {
		verificationResult, err = curve25519.MultPointScalar(verificationResult, share.IndexScalar)
		if err != nil {
			return false, fmt.Errorf("error in evaluating verification")
		}
		verificationResult, err = curve25519.AddPoint(verificationResult, curve25519.Point(verifications[j]))
		if err != nil {
			return false, fmt.Errorf("error in evaluating verification")
		}
	}

	// Check if g^{s_i} * h^{r_i} = \prod_{j=0}^{t-1}E_j^{i^j}
	return curve25519.IsEqualPoint(shareResult, verificationResult), nil
}

// VSSReconstruct reconstructs the secret shared in the Pedersen VSS scheme
func VSSReconstruct(params *Params, shares []Share, verifications []Commitment) (*Message, error) {
	t := len(verifications)
	n := len(shares)
	var validShares []Share

	// Find t valid shares to determine what points to interpolate through
	for i := 0; i < n && i-len(validShares) <= n-t && len(validShares) < t; i++ {
		isValid, err := VSSVerify(params, shares[i], verifications)
		if err != nil {
			return nil, fmt.Errorf("error in share verification")
		}

		if isValid {
			validShares = append(validShares, shares[i])
		}
	}

	if len(validShares) < t {
		return nil, fmt.Errorf("insufficient valid shares") // Unable to reconstruct due to insufficient valid shares
	}

	// Polynomial interpolation evaluated at 0
	var sum curve25519.Scalar
	for i := 0; i < t; i++ {

		term := validShares[i].S
		for j := 0; j < t; j++ {
			if i != j {
				denom, err := curve25519.InvertScalar(curve25519.SubScalar(validShares[j].IndexScalar, validShares[i].IndexScalar))
				if err != nil {
					return nil, fmt.Errorf("error in polynomial interpolation")
				}
				term = curve25519.MultScalar(term, curve25519.MultScalar(validShares[j].IndexScalar, denom))
			}
		}
		sum = curve25519.AddScalar(sum, term)
	}

	m := Message(sum)
	return &m, nil
}
