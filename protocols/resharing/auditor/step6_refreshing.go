package auditor

import (
	"fmt"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	log "github.com/sirupsen/logrus"
)

// ComputeQualifiedDealers returns the list of the first t+1 qualified dealers whose shares
// will be used for refreshing (qualifiedDealers[x] is a dealer index in 0,...,n-1)
// and the corresponding Lagrange coefficients
func ComputeQualifiedDealers(
	pub *PublicInput,
) (
	qualifiedDealers []int,
	lagrangeCoeffs []curve25519.Scalar,
	err error,
) {

	// FIXME make it correct! currently, just return first t+1 dealers

	qualifiedDealers = make([]int, pub.T+1)
	qualifiedDealersScalars := make([]curve25519.Scalar, pub.T+1)

	for i := 0; i < pub.T+1; i++ {
		qualifiedDealers[i] = i
		qualifiedDealersScalars[i] = curve25519.GetScalar(uint64(i + 1))
	}

	lagrangeCoeffs, err = curve25519.LagrangeCoeffs(qualifiedDealersScalars, curve25519.GetScalar(uint64(0)))
	if err != nil {
		return nil, nil,
		fmt.Errorf("failed to compute Lagrange coeffs for qualified dealers: %w", err)
	}

	return qualifiedDealers, lagrangeCoeffs, nil
}

// ComputeRefreshedShare returns the fresh share of a party j in the new holding committee
func ComputeRefreshedShare(
	pub *PublicInput, prv *PrivateInput, j int,
	dealingMessages []DealingMessage, verificationMessages []VerificationMessage,
	qualifiedDealers []int, lagrangeCoeffs []curve25519.Scalar,
) (
	share *vss.Share,
	err error,
) {

	verSentShares := DecryptVerSentShares(pub, prv, j, verificationMessages)

	share = &vss.Share{
		Index:       j + 1,
		IndexScalar: curve25519.GetScalar(uint64(j + 1)),
		S:           curve25519.ScalarZero,
		R:           curve25519.ScalarZero,
	}

	for _, i := range qualifiedDealers {
		sIJK, rIJK, err := ComputeShareIJ(pub, i, j, verSentShares, dealingMessages)
		if err != nil {
			return nil, err
		}

		s := curve25519.MultScalar(*sIJK, lagrangeCoeffs[i])
		r := curve25519.MultScalar(*rIJK, lagrangeCoeffs[i])

		share.S = curve25519.AddScalar(share.S, s)
		share.R = curve25519.AddScalar(share.R, r)
	}

	return share, nil
}

// ComputeShareIJ computes sigma_ij and rho_ij from the verification committee messages
// FIXME Need to use future broadcast if necessary
func ComputeShareIJ(
	pub *PublicInput, i int, j int,
	verSentShares []VerSentShares, dealingMessages []DealingMessage,
) (
	*pedersen.Message,
	*pedersen.Decommitment,
	error,
) {
	sharesIJ := make([]vss.Share, 0, pub.N) // sharesIJ[k] corresponds to sigma_ijk

	for k := 0; k < pub.N; k++ {
		if verSentShares[k].S[i] == nil || verSentShares[k].R[i] == nil {
			// FIXME: that's where we use future broadcast
			continue
		}
		sharesIJ = append(sharesIJ, vss.Share{
			Index:       k + 1,
			IndexScalar: curve25519.GetScalar(uint64(k + 1)),
			S:           *verSentShares[k].S[i],
			R:           *verSentShares[k].R[i],
		})
	}

	sIJK, rIJK, err := vss.ReconstructWithR(&pub.VSSParams, sharesIJ, dealingMessages[i].ComS[j])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct sigma/rho_{%d,%d}: %w", i, j, err)
	}
	return sIJK, rIJK, nil
}

func DecryptVerSentShares(
	pub *PublicInput, prv *PrivateInput, j int,
	verificationMessages []VerificationMessage,
) (
	verSentShares []VerSentShares,
) {
	verSentShares = make([]VerSentShares, pub.N)
	for k := 0; k < pub.N; k++ {
		m, err := curve25519.Decrypt(pub.EncPKs[prv.Id], prv.EncSK, verificationMessages[k].EncShares[j])
		if err != nil {
			// when we cannot decrypt, we continue and consider the verification committee member to be malicious
			log.Infof("could not decrypt verificationMessages[%d].EncShares[%d]", k, j)
			continue
		}

		err = msgpack.Decode(m, &verSentShares[k])
		if err != nil {
			// when we cannot decrypt, we continue and consider the verification committee member to be malicious
			log.Infof("could not decode verificationMessages[%d].EncShares[%d]", k, j)
			continue
		}
	}

	return verSentShares
}

// ComputeRefreshedCommitments returns the new commitments of the new holding committee
// Executed by all parties in the YOSO protocol
func ComputeRefreshedCommitments(
	pub *PublicInput,
	dealingMessages []DealingMessage,
	qualifiedDealers []int, lagrangeCoeffs []curve25519.Scalar,
) (
	commitments []pedersen.Commitment,
	err error,
) {

	// Recall that commitments[0] is the commitment to the secret
	// and commitments[j+1] is the commitment to the new share held by party j
	commitments = make([]pedersen.Commitment, pub.N+1)
	commitments[0] = pub.Commitments[0]
	for j := 0; j < pub.N; j++ {
		// Computing commitments[j+1] for the new holding committee member j
		// This is the Lagrange reconsturction
		// of all the original commitments S_ij for qualified dealers i
		commitments[j+1] = curve25519.PointInfinity
		for _, i := range qualifiedDealers {
			cc, err := curve25519.MultPointScalar(dealingMessages[i].ComS[j][0], lagrangeCoeffs[i])
			if err != nil {
				return nil, fmt.Errorf("error point multiplication: %w", err)
			}

			commitments[j+1], err = curve25519.AddPoint(commitments[j+1], cc)
			if err != nil {
				return nil, fmt.Errorf("error adding points: %w", err)
			}
		}
	}

	return commitments, nil
}
