package auditor

import (
	"fmt"
	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	log "github.com/sirupsen/logrus"
)

func PerformRefresh(
	pub *PublicInput,
	prv *PrivateInput,
	dealingMessages []DealingMessage,
	verificationMessages []VerificationMessage,
	resolutionMessages []ResolutionMessage,
	auditingMessages []AuditingMessage,
	indexNext int, // if >=0, the party is the member number indexNext in the next holding committee
) (
	[]pedersen.Commitment,
	*vss.Share,
	error,
) {
	resolvedSharesS, resolvedSharedR, disqualifiedDealersByComplaints, err := ResolveComplaints(
		pub, dealingMessages, verificationMessages, resolutionMessages)
	qualifiedDealers, lagrangeCoefs, err := ComputeQualifiedDealers(
		pub, auditingMessages, disqualifiedDealersByComplaints)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute qualified dealers: %w", err)
	}
	log.WithField("indexNext", indexNext).WithField("party", prv.Id).Infof("qualified dealers: %v", qualifiedDealers)
	nextCommitments, err := ComputeRefreshedCommitments(pub, dealingMessages, qualifiedDealers, lagrangeCoefs)
	var nextShare *vss.Share
	if indexNext >= 0 {
		// We're in the next committee
		nextShare, err = ComputeRefreshedShare(
			pub, prv, indexNext,
			dealingMessages, verificationMessages,
			qualifiedDealers, lagrangeCoefs,
			resolvedSharesS, resolvedSharedR,
		)
		if err != nil {
			return nil, nil, err
		}
	}
	return nextCommitments, nextShare, nil
}

// isDealerQualified checks wheter dealer i is qualified according to auditing messages
// i.e., more than n/2 auditors marked them as qualified
func isDealerQualified(
	n int,
	i int,
	auditingMessages []AuditingMessage,
) bool {

	// a dealer is qualified is more than half of the auditor marked them as qualified
	cnt := 0
	for l := 0; l < n; l++ {
		if auditingMessages[l].QualifiedDealers[i] {
			cnt++
		}
	}

	return cnt > n/2
}

// ComputeQualifiedDealers returns the list of the first t+1 qualified dealers whose shares
// will be used for refreshing (qualifiedDealers[x] is a dealer index in 0,...,n-1)
// and the corresponding Lagrange coefficients
// disqualifiedDealersByComplaints is an output of ResolveComplaints
func ComputeQualifiedDealers(
	pub *PublicInput,
	auditingMessages []AuditingMessage,
	disqualifiedDealersByComplaints map[int]bool,
) (
	qualifiedDealers []int,
	lagrangeCoeffs []curve25519.Scalar,
	err error,
) {
	qualifiedDealers = make([]int, pub.T+1)
	qualifiedDealersScalars := make([]curve25519.Scalar, pub.T+1)

	// Find the first t+1 qualified dealers
	ii := 0
	for i := 0; i < pub.N && ii < pub.T+1; i++ {
		if _, ok := disqualifiedDealersByComplaints[i]; ok {
			// disqualified by complaints
			continue
		}
		if isDealerQualified(pub.N, i, auditingMessages) {
			qualifiedDealers[ii] = i
			qualifiedDealersScalars[ii] = *curve25519.GetScalar(uint64(i + 1))
			ii++
		}
	}
	if ii != pub.T+1 {
		return nil, nil, fmt.Errorf("not enough qualified dealers: found %d, but need t+1=%d", ii, pub.T+1)
	}

	// Compute the Lagrange coefficients
	lagrangeCoeffs, err = curve25519.LagrangeCoeffs(qualifiedDealersScalars, curve25519.GetScalar(uint64(0)))
	if err != nil {
		return nil, nil,
			fmt.Errorf("failed to compute Lagrange coeffs for qualified dealers: %w", err)
	}

	return qualifiedDealers, lagrangeCoeffs, nil
}

// ComputeRefreshedShare returns the fresh share of a party j in the new holding committee
// resolvedSharesS, resolvedSharesR come from ResolveComplaints (i.e., via future broadcast)
func ComputeRefreshedShare(
	pub *PublicInput, prv *PrivateInput, j int,
	dealingMessages []DealingMessage, verificationMessages []VerificationMessage,
	qualifiedDealers []int, lagrangeCoeffs []curve25519.Scalar,
	resolvedSharesS, resolvedSharesR map[TripleIJK]curve25519.Scalar,
) (
	share *vss.Share,
	err error,
) {

	verSentShares := DecryptVerSentShares(pub, prv, j, verificationMessages)

	share = &vss.Share{
		Index:       j + 1,
		IndexScalar: *curve25519.GetScalar(uint64(j + 1)),
		S:           curve25519.ScalarZero,
		R:           curve25519.ScalarZero,
	}

	sumS := &curve25519.Scalar{}
	sumR := &curve25519.Scalar{}
	*sumS = curve25519.ScalarZero
	*sumR = curve25519.ScalarZero

	for ii, i := range qualifiedDealers {
		sIJK, rIJK, err := ComputeShareIJ(pub, i, j, verSentShares, dealingMessages, resolvedSharesS, resolvedSharesR)
		if err != nil {
			return nil, err
		}

		s := curve25519.MultScalar(sIJK, &lagrangeCoeffs[ii])
		r := curve25519.MultScalar(rIJK, &lagrangeCoeffs[ii])

		sumS = curve25519.AddScalar(sumS, s)
		sumR = curve25519.AddScalar(sumR, r)
	}

	share.S = *sumS
	share.R = *sumR

	return share, nil
}

// ComputeShareIJ computes sigma_ij and rho_ij from the verification committee messages
// resolvedSharesS, resolvedSharesR come from ResolveComplaints (i.e., via future broadcast)
func ComputeShareIJ(
	pub *PublicInput, i int, j int,
	verSentShares []VerSentShares, dealingMessages []DealingMessage,
	resolvedSharesS, resolvedSharesR map[TripleIJK]curve25519.Scalar,
) (
	*pedersen.Message,
	*pedersen.Decommitment,
	error,
) {
	sharesIJ := make([]vss.Share, 0, pub.N) // sharesIJ[k] corresponds to sigma_ijk

	for k := 0; k < pub.N; k++ {
		if _, ok := resolvedSharesS[TripleIJK{i, j, k}]; ok {
			// If future broadcast/resolution is available, we must use that
			log.Infof("use resolved shares for i=%d,j=%d,k=%d", i, j, k)

			sharesIJ = append(sharesIJ, vss.Share{
				Index:       k + 1,
				IndexScalar: *curve25519.GetScalar(uint64(k + 1)),
				S:           resolvedSharesS[TripleIJK{i, j, k}],
				R:           resolvedSharesR[TripleIJK{i, j, k}],
			})
		} else if len(verSentShares[k].S) == pub.N && len(verSentShares[k].R) == pub.N &&
			verSentShares[k].S[i] != nil && verSentShares[k].R[i] != nil {
			// Otherwise we use the shares from the verification committee if available

			sharesIJ = append(sharesIJ, vss.Share{
				Index:       k + 1,
				IndexScalar: *curve25519.GetScalar(uint64(k + 1)),
				S:           *verSentShares[k].S[i],
				R:           *verSentShares[k].R[i],
			})
		}
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
		if len(verificationMessages[k].EncShares) != pub.N {
			// when the length is incorrect, we continue and consider the verification committee member to be malicious
			log.Infof("verificationMessages[%d].EncShares has incorrect length", k)
			continue
		}

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
		com := &curve25519.Point{}
		*com = curve25519.PointInfinity
		for ii, i := range qualifiedDealers {
			cc, err := curve25519.MultPointScalar(&dealingMessages[i].ComS[j][0], &lagrangeCoeffs[ii])
			if err != nil {
				return nil, fmt.Errorf("error point multiplication: %w", err)
			}

			com, err = curve25519.AddPoint(com, cc)
			if err != nil {
				return nil, fmt.Errorf("error adding points: %w", err)
			}
		}
		commitments[j+1] = *com
	}

	return commitments, nil
}
