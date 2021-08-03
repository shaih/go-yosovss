package vss

// oldvss contains the old way of doing the VSS
// namely commitments are commitments of the evaluation of the polynomials/shared
// randomness for commitments is secret-shared using a pol of degree d

import (
	"fmt"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// Share is composed of values used in Pedersen VSS to reconstruct a secret
type Share struct {
	Index       int               // i \in {1,...,n}
	IndexScalar curve25519.Scalar // same as i but as a scalar
	S           curve25519.Scalar // sigma_i
	R           curve25519.Scalar // rho_i (commitments[i] = Pedersen(S, R) = S * G + R * H
}

type Params struct {
	PedersenParams *pedersen.Params
	D              int // degree of the polynomial (reconstruction threshold t = d+1)
	N              int // number of shares
}

func checkCommitmentsLength(params *Params, commitments []pedersen.Commitment) error {
	n := params.N
	if len(commitments) != n+1 {
		return fmt.Errorf("number of commitments is %d not equal to n+1 = %d",
			len(commitments),
			n+1,
		)
	}
	return nil
}

func checkSharesLength(params *Params, shares []Share) error {
	n := params.N
	if len(shares) != n {
		return fmt.Errorf("number of shares is %d not equal to n = %d",
			len(shares),
			n,
		)
	}
	return nil
}

// Reconstruct reconstructs the secret shared in the Pedersen VSS scheme
// It assumes that commitments are valid, i.e., they are indeed committing to evaluations of a degree-d polynomial
func Reconstruct(params *Params, shares []Share, commitments []pedersen.Commitment) (*pedersen.Message, error) {
	n := params.N
	d := params.D
	t := d + 1 // reconstruction threshold

	var validShares []Share
	var err error

	err = checkCommitmentsLength(params, commitments)
	if err != nil {
		return nil, err
	}
	err = checkSharesLength(params, shares)
	if err != nil {
		return nil, err
	}

	// Find t valid shares to determine what points to interpolate through
	for i := 0; i < n && i-len(validShares) <= n-t && len(validShares) < t; i++ {
		isValid, err := VerifyShare(params, &shares[i], commitments)
		if err != nil {
			return nil, fmt.Errorf("error verifying share: %w", err)
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
	validShareValues := make([]curve25519.Scalar, t)
	for i := 0; i < t; i++ {
		validShareValues[i] = validShares[i].IndexScalar
	}
	lambdas, err := curve25519.LagrangeCoeffs(validShareValues, curve25519.GetScalar(uint64(0)))
	if err != nil {
		return nil, fmt.Errorf("error in polynomial interpolation")
	}

	for i := 0; i < t; i++ {
		sum = curve25519.AddScalar(sum, curve25519.MultScalar(validShares[i].S, lambdas[i]))
	}

	m := pedersen.Message(sum)
	return &m, nil
}

// FixedRShare performs the initial dealer's step for a Pedersen VSS on the secret s
// for t-of-n reconstruction, but with a fixed r that is the constant of the g polynomial.
func FixedRShare(params *Params, s curve25519.Scalar, r curve25519.Scalar) ([]Share, []pedersen.Commitment, error) {
	n := params.N
	d := params.D
	t := d + 1 // reconstruction threshold

	if t < 0 || n <= 1 || t > params.N {
		return nil, nil, fmt.Errorf("invalid share generation parameters")
	}

	// The shares to be distributed to participants
	shares := make([]Share, n)

	// The commitments to the shares
	commitments := make([]pedersen.Commitment, n+1)

	// Polynomial used to share the secret s
	f := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_{t-1} * x^{t-1} where a_0 = m and a_1,...,a_{t-1} are random

	// Polynomial used to share the randomness r
	g := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // g(x) = b_0 + b_1 * x + b_2 * x^2 + ... + b_{t-1} * x^{t-1} where b_0 = r and b_1,...,b_{t-1} are random

	// Get commitment to the secret
	commitment, err := pedersen.GenerateCommitmentFixedR(
		params.PedersenParams,
		pedersen.Message(s),
		pedersen.Decommitment(r),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating message commitment: %w", err)
	}
	f.Coefficients[0] = s
	g.Coefficients[0] = r
	commitments[0] = *commitment

	// Generate random values for remaining coefficients
	for i := 1; i < t; i++ {
		f.Coefficients[i] = curve25519.RandomScalar()
		g.Coefficients[i] = curve25519.RandomScalar()
	}

	// Perform Shamir secret sharing on the generated polynomials to construct shares
	evalPoint := curve25519.ScalarZero
	for i := 1; i <= n; i++ {
		// NOTE: Expensive step, consider changing in the future
		evalPoint = curve25519.AddScalar(evalPoint, curve25519.ScalarOne)

		shares[i] = Share{
			Index:       i,
			IndexScalar: evalPoint,
			S:           f.Evaluate(evalPoint),
			R:           g.Evaluate(evalPoint),
		} // The share of participant i is (sigma_i, rho_i) = (f(i), g(i))

		// Compute the commitment to the share using randomness rho_i
		commitment, err = pedersen.GenerateCommitmentFixedR(
			params.PedersenParams,
			pedersen.Message(shares[i].S),
			pedersen.Decommitment(shares[i].R),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating commitment of share %d: %w", i, err)
		}
		commitments[i] = *commitment
	}

	return shares, commitments, nil
}

// VerifyShare verifies that a share matches its commitment
// It assumes (and does not verify) that the commitments are on a polynomial of degree d
// i.e., that VerifyCommitments is true
func VerifyShare(params *Params, share *Share, commitments []pedersen.Commitment) (bool, error) {
	err := checkCommitmentsLength(params, commitments)
	if err != nil {
		return false, err
	}

	if share.Index <= 0 || share.Index >= params.N {
		return false, fmt.Errorf("invalid share index %d (not between 1 and n-1)", share.Index)
	}

	return pedersen.VerifyCommitment(
		params.PedersenParams,
		&commitments[share.Index],
		pedersen.Message(share.S),
		(*pedersen.Decommitment)(&share.R),
	)
}

// VerifyCommitments verifies that the commitments are consistent
// i.e., they are on a polynomial of degree d
func VerifyCommitments(params *pedersen.Params, share Share, verifications []pedersen.Commitment) (bool, error) {
	// TODO
	return false, nil
}
