package oldvss

// oldvss contains the old way of doing the VSS
// namely verification commitments are commitments to the coefficients of the polynomials
// as opposed to the new way to do it in YOSO
// where commitments are commitments to shares instead

import (
	"fmt"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// Share is composed of values used in Pedersen VSS to reconstruct a secret
type Share struct {
	Index       int
	IndexScalar curve25519.Scalar
	S           curve25519.Scalar
	R           curve25519.Scalar
}

// VSSReconstruct reconstructs the secret shared in the Pedersen VSS scheme
func VSSReconstruct(params *pedersen.Params, shares []Share, verifications []pedersen.Commitment) (
	*pedersen.Message, error) {
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

// VSSShare performs the initial dealer's step for a Pedersen VSS on the message m
// for t-of-n reconstruction.
func VSSShare(params *pedersen.Params, m pedersen.Message, t int, n int) ([]Share, []pedersen.Commitment, error) {
	if t < 1 || n < 1 || t > n {
		return nil, nil, fmt.Errorf("invalid share generation parameters")
	}

	// The shares to be distributed to participants
	var shares []Share

	// The commitments to the coefficient of polynomials used to verify
	// correctness of shares
	var verifications []pedersen.Commitment

	f := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_{t-1} * x^{t-1} where a_0 = m and a_1,...,a_{t-1} are random
	g := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // g(x) = b_0 + b_1 * x + b_2 * x^2 + ... + b_{t-1]} * x^{t-1} where b_0,...,b_{t-1} are random

	// Get commitment to the secret
	commitment, decommitment, err := pedersen.GenerateCommitment(params, m)
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
		commitment, decommitment, err = pedersen.GenerateCommitment(params, pedersen.Message(f.Coefficients[i]))
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

// VSSShareFixedR performs the initial dealer's step for a Pedersen VSS on the message m
// for t-of-n reconstruction, but with a fixed r that is the constant of the g polynomial.
func VSSShareFixedR(params *pedersen.Params, m pedersen.Message, r pedersen.Decommitment, t int, n int) (
	[]Share, []pedersen.Commitment, error) {
	if t < 1 || n < 1 || t > n {
		return nil, nil, fmt.Errorf("invalid share generation parameters")
	}

	// The shares to be distributed to participants
	var shares []Share

	// The commitments to the coefficient of polynomials used to verify
	// correctness of shares
	var verifications []pedersen.Commitment

	f := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_{t-1} * x^{t-1} where a_0 = m and a_1,...,a_{t-1} are random
	g := curve25519.Polynomial{
		Coefficients: make([]curve25519.Scalar, t),
	} // g(x) = b_0 + b_1 * x + b_2 * x^2 + ... + b_{t-1} * x^{t-1} where b_0 = r and b_1,...,b_{t-1} are random

	// Get commitment to the secret
	commitment, err := pedersen.GenerateCommitmentFixedR(params, m, r)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating message commitment")
	}
	f.Coefficients[0] = curve25519.Scalar(m)
	g.Coefficients[0] = curve25519.Scalar(r)

	verifications = append(verifications, *commitment)

	// Generate random values for remaining coefficients
	for i := 1; i < t; i++ {
		f.Coefficients[i] = curve25519.RandomScalar()
		// Get commitment the random polynomial coefficients
		commitment, decommitment, err := pedersen.GenerateCommitment(params, pedersen.Message(f.Coefficients[i]))
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
func VSSVerify(params *pedersen.Params, share Share, verifications []pedersen.Commitment) (bool, error) {
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
	return curve25519.PointEqual(shareResult, verificationResult), nil
}
