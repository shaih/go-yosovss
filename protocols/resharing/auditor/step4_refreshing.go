package auditor

import (
	"fmt"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/shamir"
	log "github.com/sirupsen/logrus"
)

func PerformRefresh(
	pub *PublicInput,
	prv *PrivateInput,
	dealingMessages []DealingMessage,
	verificationMessages []VerificationMessage,
	resolutionMessages []ResolutionMessage,
	indexNext int, // if >=0, the party is the member number indexNext in the next holding committee
	dbg *PartyDebugParams,
) (
	[]pedersen.Commitment,
	*shamir.Share,
	error,
) {
	resolvedSharesS, disqualifiedDealersByComplaints, err := ResolveComplaints(
		pub, dealingMessages, verificationMessages, resolutionMessages, dbg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve complaints: %w", err)
	}
	qualifiedDealers, lagrangeCoefs, err := ComputeQualifiedDealers(
		pub, disqualifiedDealersByComplaints)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute qualified dealers: %w", err)
	}
	log.WithField("indexNext", indexNext).WithField("party", prv.ID).Infof("qualified dealers: %v", qualifiedDealers)
	nextCommitments, err := ComputeRefreshedCommitments(pub, dealingMessages, qualifiedDealers, lagrangeCoefs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute refreshed commitments: %w", err)
	}
	var nextShare *shamir.Share
	if indexNext >= 0 {
		// We're in the next committee
		nextShare, err = ComputeRefreshedShare(
			pub, prv, indexNext,
			dealingMessages, verificationMessages,
			qualifiedDealers, lagrangeCoefs,
			resolvedSharesS,
		)
		if err != nil {
			return nil, nil, err
		}
	}
	return nextCommitments, nextShare, nil
}

// ComputeQualifiedDealers returns the list of the first t+1 qualified dealers whose shares
// will be used for refreshing (qualifiedDealers[x] is a dealer index in 0,...,n-1)
// and the corresponding Lagrange coefficients
// disqualifiedDealersByComplaints is an output of ResolveComplaints
func ComputeQualifiedDealers(
	pub *PublicInput,
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
		// TODO MAKE OTHER CHECK THERE
		//if isDealerQualified(pub.N, i, auditingMessages) {
		qualifiedDealers[ii] = i
		qualifiedDealersScalars[ii] = *curve25519.GetScalar(uint64(i + 1))
		ii++
		//}
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
	pub *PublicInput, prv *PrivateInput, l int,
	dealingMessages []DealingMessage, verificationMessages []VerificationMessage,
	qualifiedDealers []int, lagrangeCoeffs []curve25519.Scalar,
	resolvedSharesS map[TripleIJL]curve25519.Scalar,
) (
	share *shamir.Share,
	err error,
) {

	verSentShares := DecryptVerSentShares(pub, prv, l, verificationMessages)

	share = &shamir.Share{
		Index:       l + 1,
		IndexScalar: *curve25519.GetScalar(uint64(l + 1)),
		S:           curve25519.ScalarZero,
	}

	sumS := &curve25519.Scalar{}
	*sumS = curve25519.ScalarZero

	for ii, i := range qualifiedDealers {
		sIL, err := ComputeShareIL(pub, i, l, verSentShares, dealingMessages, resolvedSharesS)
		if err != nil {
			return nil, err
		}

		s := curve25519.MultScalar(sIL, &lagrangeCoeffs[ii])
		sumS = curve25519.AddScalar(sumS, s)
	}

	share.S = *sumS

	return share, nil
}

// ComputeShareIL computes sigma_{i+1,l+1} = sigma_{i+1,0,l+1} from shares from verification committee
// and future broadcast
// resolvedSharesS, resolvedSharesR come from ResolveComplaints (i.e., via future broadcast)
// l in [0,n-1]
func ComputeShareIL(
	pub *PublicInput, i int, l int,
	verSentShares []VerSentShares, dealingMessages []DealingMessage,
	resolvedSharesS map[TripleIJL]curve25519.Scalar,
) (
	*curve25519.Scalar,
	error,
) {
	sharesIL := make([]shamir.Share, 0, pub.VSSParams.D+1) // sharesIL[j] corresponds to sigma_ijl

	// Get the first T valid shares
	for j := 0; j < pub.N && len(sharesIL) < pub.VSSParams.D+1; j++ {
		if _, ok := resolvedSharesS[TripleIJL{i, j, l + 1}]; ok {
			// If future broadcast/resolution is available, we must use that
			// Note that these shares are necessarily ok because verified to match C_ij
			log.Infof("use resolved shares for i=%d,j=%d,l=%d", i, j, l)

			sharesIL = append(sharesIL, shamir.Share{
				Index:       j + 1,
				IndexScalar: *curve25519.GetScalar(uint64(j + 1)),
				S:           resolvedSharesS[TripleIJL{i, j, l + 1}],
			})
		} else if len(verSentShares[j].S) == pub.N && verSentShares[j].S[i] != nil {
			// Otherwise we use the shares from the verification committee if available
			// TODO TODO
			// TODO ADD TESTS THAT VERIFY V_j BEFORE

			sharesIL = append(sharesIL, shamir.Share{
				Index:       j + 1,
				IndexScalar: *curve25519.GetScalar(uint64(j + 1)),
				S:           *verSentShares[j].S[i],
			})
		}
	}

	if len(sharesIL) != pub.VSSParams.D+1 {
		panic("not enough shares")
	}

	// TODO: optimize with dirty optimization precomputed lagrangian
	sIL, err := shamir.Reconstruct(sharesIL)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct sigma_{i+1,l+1} for i=%d, l=%d: %w", i, l, err)
	}
	return sIL, nil
}

func DecryptVerSentShares(
	pub *PublicInput, prv *PrivateInput, l int,
	verificationMessages []VerificationMessage,
) (
	verSentShares []VerSentShares,
) {
	verSentShares = make([]VerSentShares, pub.N)
	for j := 0; j < pub.N; j++ {
		if len(verificationMessages[j].EncShares) != pub.N {
			// when the length is incorrect, we continue and consider the verification committee member to be malicious
			log.Infof("verificationMessages[%d].EncShares has incorrect length", j)
			continue
		}

		m, err := curve25519.Decrypt(pub.EncPKs[prv.ID], prv.EncSK, verificationMessages[j].EncShares[l])
		if err != nil {
			// when we cannot decrypt, we continue and consider the verification committee member to be malicious
			log.Infof("could not decrypt verificationMessages[%d].EncShares[%d]", j, l)
			continue
		}

		err = msgpack.Decode(m, &verSentShares[j])
		if err != nil {
			// when we cannot decrypt, we continue and consider the verification committee member to be malicious
			log.Infof("could not decode verificationMessages[%d].EncShares[%d]", j, l)
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

	//// Recall that commitments[0] is the commitment to the secret
	//// and commitments[j+1] is the commitment to the new share held by party j
	//commitments = make([]pedersen.Commitment, pub.N+1)
	//commitments[0] = pub.OldPedCommitments[0]
	//comSJ := make([]curve25519.PointXY, pub.T+1)
	//for j := 0; j < pub.N; j++ {
	//	// Computing commitments[j+1] for the new holding committee member j
	//	// This is the Lagrange reconsturction
	//	// of all the original commitments S_ij for qualified dealers i
	//
	//	// Old slow code
	//	//com := &curve25519.PointXY{}
	//	//*com = curve25519.PointXYInfinity
	//	//for ii, i := range qualifiedDealers {
	//	//	cc, err := curve25519.MultPointXYScalar(&dealingMessages[i].OldComS[j][0], &lagrangeCoeffs[ii])
	//	//	if err != nil {
	//	//		return nil, fmt.Errorf("error point multiplication: %w", err)
	//	//	}
	//	//
	//	//	com, err = curve25519.AddPointXY(com, cc)
	//	//	if err != nil {
	//	//		return nil, fmt.Errorf("error adding points: %w", err)
	//	//	}
	//	//}
	//
	//	// Faster code
	//	for ii, i := range qualifiedDealers {
	//		comSJ[ii] = dealingMessages[i].OldComS[j][0]
	//	}
	//	com, err := curve25519.MultiMultPointXYScalarVarTime(comSJ, lagrangeCoeffs)
	//	if err != nil {
	//		return nil, fmt.Errorf("error refresh commitments: %w", err)
	//	}
	//	commitments[j+1] = *com
	//}

	// TODO

	return nil, nil
}
