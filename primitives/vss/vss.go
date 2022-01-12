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
	PedersenParams     *pedersen.Params
	N                  int                     // number of shares
	D                  int                     // degree of the polynomial (reconstruction threshold t = d+1)
	ParityMatrix       curve25519.ScalarMatrix // paritycpp-check matrix size = (n+1) * (n+1-t)
	LagrangeCoefsFirst []curve25519.Scalar     // Lagrange coefficients for 1,...,d+1.
	// Used for a dirty optimization when the first d+1 shares are valid
}

func NewVSSParams(pedersenParams *pedersen.Params, n, d int) (*Params, error) {
	pm, err := ComputeParityMatrix(n, d+1)
	if err != nil {
		return nil, err
	}

	firstIndices := make([]curve25519.Scalar, d+1)
	for i := 0; i < d+1; i++ {
		curve25519.GetScalarC(&firstIndices[i], uint64(i+1))
	}
	lagrangeCoefsFirst, err := curve25519.LagrangeCoeffs(firstIndices, &curve25519.ScalarZero)
	if err != nil {
		return nil, err
	}

	return &Params{
		PedersenParams:     pedersenParams,
		N:                  n,
		D:                  d,
		ParityMatrix:       *pm,
		LagrangeCoefsFirst: lagrangeCoefsFirst,
	}, nil
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
// Use VerifyCommitments to verify the above property
// See FixedRShare see how commitments are defined
//
// Shares need to contain at least t valid shares. It may contain invalid shares.
// But it must not contain two shares with the same index, and all index/indexScalar of the shares are supposed valid
// Only shares[i].R and shares[i].SR may be invalid.
//
// FIXME: not as efficient as it could be as it reconstruct the randomness R too
func Reconstruct(params *Params, shares []Share, commitments []pedersen.Commitment) (*pedersen.Message, error) {
	s, _, err := ReconstructWithR(params, shares, commitments)

	return s, err
}

// ReconstructWithR is like Reconstruct except it also reconstructs the randomness/decommitment r
// Optimized when the shares are in order of indices and the first d+1 shares are all valid
// because it has the Lagrange coefs precomputed in that case.
// FIXME: It's a bit dirty...
func ReconstructWithR(params *Params, shares []Share, commitments []pedersen.Commitment) (
	*pedersen.Message, *pedersen.Decommitment, error) {
	n := params.N
	d := params.D
	t := d + 1 // reconstruction threshold

	var validShares []Share
	var err error

	err = checkCommitmentsLength(params, commitments)
	if err != nil {
		return nil, nil, err
	}

	// Find t valid shares to determine what points to interpolate through
	for i := 0; i < len(shares) && i-len(validShares) <= n-t && len(validShares) < t; i++ {
		isValid, err := VerifyShare(params, &shares[i], commitments)
		if err != nil {
			return nil, nil, fmt.Errorf("error verifying share: %w", err)
		}

		if isValid {
			validShares = append(validShares, shares[i])
		}
	}

	if len(validShares) < t {
		// Unable to reconstruct due to insufficient valid shares
		return nil, nil, fmt.Errorf("insufficient valid shares")
	}

	// Polynomial interpolation evaluated at 0
	validShareValues := make([]curve25519.Scalar, t)
	areFirstIndices := true // is true iff the valid indices are 1,...,t in this order
	for i := 0; i < t; i++ {
		validShareValues[i] = validShares[i].IndexScalar
		if i+1 != validShares[i].Index {
			areFirstIndices = false
		}
	}
	var lambdas []curve25519.Scalar
	if areFirstIndices {
		lambdas = params.LagrangeCoefsFirst
	} else {
		lambdas, err = curve25519.LagrangeCoeffs(validShareValues, curve25519.GetScalar(uint64(0)))
		if err != nil {
			return nil, nil, fmt.Errorf("error in polynomial interpolation")
		}
	}

	// Reconstruct message via pol interpolation at 0
	s := &curve25519.Scalar{}
	*s = curve25519.ScalarZero
	for i := 0; i < t; i++ {
		s = curve25519.AddScalar(s, curve25519.MultScalar(&validShares[i].S, &lambdas[i]))
	}

	// Reconstruct randomness/decommitment
	r := &curve25519.Scalar{}
	*r = curve25519.ScalarZero
	for i := 0; i < t; i++ {
		r = curve25519.AddScalar(r, curve25519.MultScalar(&validShares[i].R, &lambdas[i]))
	}

	return s, r, nil
}

// FixedRShare performs the initial dealer's step for a Pedersen VSS on the secret s
// for t-of-n reconstruction, but with a fixed r that is the constant of the g polynomial.
//
// shares has length n
// commitments has length n+1
// commitments[0] is the Pedersen commitment of the secret s with randomness r
// commitments[i] for i > 1 is the Pedersen commitment of the share of index i, that is shares[i-1]
func FixedRShare(params *Params, s, r *curve25519.Scalar) (
	shares []Share, commitments []pedersen.Commitment, err error) {

	n := params.N
	d := params.D
	t := d + 1 // reconstruction threshold

	if t < 0 || n <= 1 || t > params.N {
		return nil, nil, fmt.Errorf("invalid share generation parameters")
	}

	// The shares to be distributed to participants
	shares = make([]Share, n)

	// The commitments to the shares
	commitments = make([]pedersen.Commitment, n+1)

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
		s,
		r,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating message commitment: %w", err)
	}
	f.Coefficients[0] = *s
	g.Coefficients[0] = *r
	commitments[0] = *commitment

	// Generate random values for remaining coefficients
	chacha20Key, err := curve25519.RandomChacha20Key()
	if err != nil {
		return nil, nil, err
	}
	for i := 1; i < t; i++ {
		curve25519.RandomScalarChacha20C(&f.Coefficients[i], &chacha20Key, uint64(2*i))
		curve25519.RandomScalarChacha20C(&g.Coefficients[i], &chacha20Key, uint64(2*i+1))
	}

	// Perform Shamir secret sharing on the generated polynomials to construct shares
	for i := 1; i <= n; i++ {
		// The share of participant i is (sigma_i, rho_i) = (f(i), g(i))
		shares[i-1].Index = i
		curve25519.GetScalarC(&shares[i-1].IndexScalar, uint64(i))
		f.EvaluateC(&shares[i-1].S, &shares[i-1].IndexScalar)
		g.EvaluateC(&shares[i-1].R, &shares[i-1].IndexScalar)

		// Compute the commitment to the share using randomness rho_i
		commitment, err = pedersen.GenerateCommitmentFixedR(
			params.PedersenParams,
			&shares[i-1].S,
			&shares[i-1].R,
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

	if share.Index < 1 || share.Index > params.N {
		return false, fmt.Errorf("invalid share index %d (not between 1 and n)", share.Index)
	}

	return pedersen.VerifyCommitment(
		params.PedersenParams,
		&commitments[share.Index],
		&share.S,
		&share.R,
	)
}

// VerifyCommitments verifies that the commitments are consistent
// i.e., they are on a polynomial of degree d
func VerifyCommitments(params *Params, commitments []pedersen.Commitment) (bool, error) {
	n := params.N
	d := params.D

	err := checkCommitmentsLength(params, commitments)
	if err != nil {
		return false, err
	}

	comVector := curve25519.PointXYMatrixFromEntries(1, n+1, commitments)
	y, err := curve25519.PointXYMatrixScalarMatrixMul(comVector, &params.ParityMatrix)
	if err != nil {
		return false, err
	}

	// Checking that the vector y is zero
	zero := true
	for j := 0; j < n-d; j++ {
		if !curve25519.PointXYEqual(&curve25519.PointXYInfinity, y.At(0, j)) {
			zero = false
			break
		}
	}
	return zero, nil
}

// VerifyCommitmentsRandomized is similar to VerifyCommitments
// except it uses a randomized test
// it picks a random vector v in the image of the parity matrix
// probability of failure = 1/p which is negligible
// It is the combination of GenerateVectorV and VerifyCommitmentsWithVectorV
func VerifyCommitmentsRandomized(params *Params, commitments []pedersen.Commitment) (bool, error) {
	vectorV, err := GenerateVectorV(params)
	if err != nil {
		return false, err
	}

	return VerifyCommitmentsWithVectorV(params, commitments, vectorV)
}

// VerifyCommitmentsWithVectorV verifies commitments using a vector v in the image of the parity matrix
// See VerifyCommitmentsRandomized
func VerifyCommitmentsWithVectorV(
	params *Params,
	commitments []pedersen.Commitment,
	vectorV *curve25519.ScalarMatrix,
) (bool, error) {
	n := params.N

	err := checkCommitmentsLength(params, commitments)
	if err != nil {
		return false, err
	}

	if vectorV.Columns() != 1 || vectorV.Rows() != n+1 {
		return false, fmt.Errorf("VerifyCommitmentsWithVectorV: wrong size of vector v")
	}

	// Multiply commitments by v
	y, err := curve25519.MultiMultPointXYScalarVarTime(commitments, vectorV.Entries())
	if err != nil {
		return false, err
	}

	return curve25519.PointXYEqual(&curve25519.PointXYInfinity, y), nil

	//comVector := curve25519.PointXYMatrixFromEntries(1, n+1, commitments)
	//
	//// Multiply comVector by v
	//y, err := curve25519.PointXYMatrixScalarMatrixMul(comVector, vectorV)
	//if err != nil {
	//	return false, err
	//}
	//
	//return curve25519.PointXYEqual(&curve25519.PointXYInfinity, y.At(0, 0)), nil
}

// GenerateVectorV generates a random vector v in the image of the parity matrix
// See VerifyCommitmentsRandomized
func GenerateVectorV(
	params *Params,
) (
	vectorV *curve25519.ScalarMatrix,
	err error,
) {
	n := params.N
	d := params.D

	// Generate a random vector u
	uVector := curve25519.NewScalarMatrix(n-d, 1)
	err = uVector.Random()
	if err != nil {
		return nil, err
	}

	// Multiply the parity matrix by the vector u to get a random vector v in the image of the parity matrix
	vectorV, err = curve25519.ScalarMatrixMul(&params.ParityMatrix, uVector)
	if err != nil {
		return nil, err
	}

	return vectorV, nil
}
