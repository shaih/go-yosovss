package auditor

import (
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	log "github.com/sirupsen/logrus"
)

type TripleIJK struct {
	i int
	j int
	k int
}

// CheckDealingMessages check if msg is valid
// If not, print an info log message
func CheckDealingMessages(pub *PublicInput, msg DealingMessage, i int) bool {
	// TODO: we actually may need to do that before ResolveComplaints
	// TODO" tests may not be sufficient

	n := pub.N

	// Check dealer message are valid and disqualify if invalid
	if len(msg.EncResM) != n ||
		len(msg.HashEps) != n ||
		len(msg.EncVerM) != n ||
		len(msg.ComS) != n {
		log.Infof("dealer %d disqualified as it sent incorrect message", i)
		return false
	}

	for j := 0; j < n; j++ {
		// TODO FIXME: we need to check that the point in ComS is valid too
		// and most likely different than point at infinity as libsodium does not like point at infinity
		// for exponentiation
		// FIXME

		if len(msg.ComS[j]) != n+1 {
			log.Infof("dealer %d disqualified as it sent incorrect message", i)
			return false
		}
	}

	for k := 0; k < n; k++ {
		if len(msg.HashEps) != n {
			log.Infof("dealer %d disqualified as it sent incorrect message", i)
			return false
		}
	}

	return true
}

// ResolveComplaints find all the complaints by verification committees,
// reconstruct the eps keys from the resolution committee members broadcast
// decrypt the EncResM messages and verify shares match the Pedersen commitments
// if decryption fails or if it leads to incorrect shares, it make the dealer disqualified
//   (disqualifiedDealers[i] = true)
// otherwise it stores the relevant shares in resolvedSharesS (for sigma) and resolvedSharesR (for rho)
func ResolveComplaints(
	pub *PublicInput,
	dealingMessages []DealingMessage,
	verificationMessages []VerificationMessage,
	resolutionMessages []ResolutionMessage,
) (
	resolvedSharesS, resolvedSharesR map[TripleIJK]curve25519.Scalar,
	disqualifiedDealers map[int]bool,
	err error,
) {
	n := pub.N

	resolvedSharesS = map[TripleIJK]curve25519.Scalar{}
	resolvedSharesR = map[TripleIJK]curve25519.Scalar{}

	disqualifiedDealers = map[int]bool{}

	for i := 0; i < n; i++ {
		if !CheckDealingMessages(pub, dealingMessages[i], i) {
			disqualifiedDealers[i] = true
			continue
		}

		for k := 0; k < n; k++ {
			if len(verificationMessages[k].Complaints) == n && verificationMessages[k].Complaints[i] {
				// Vk complained against dealer i

				// Recovering epsShares (eps_{k+1,l+1}) we can
				epsShares := make([]*curve25519.Scalar, n)
				for l := 0; l < n; l++ {
					epsIKL, ok := resolutionMessages[l].EpsShares[PairIK{i, k}]
					if ok {
						epsShares[l] = &epsIKL
					}
				}

				// Get the M[k] by reconstructing the key and decrypting it
				// also verify shares are valid
				mk := getAndVerifyResolutionMK(pub, &dealingMessages[i], epsShares, i, k)
				if mk == nil {
					// impossible to get a correct MK, reject
					disqualifiedDealers[i] = true
					break
				}

				// Store the shares
				for j := 0; j < n; j++ {
					resolvedSharesS[TripleIJK{i, j, k}] = mk.S[j]
					resolvedSharesR[TripleIJK{i, j, k}] = mk.R[j]
				}
			}
		}
	}

	return
}

func getAndVerifyResolutionMK(
	pub *PublicInput,
	msg *DealingMessage,
	epsShares []*curve25519.Scalar,
	i int,
	k int,
) *VerificationMK {
	n := pub.N

	// Reconstructing the key
	epsKey, err := ReconstructEpsKey(n, pub.T, epsShares, msg.HashEps[k])
	if err != nil {
		log.Infof("dealer %d provided incorrect shares to resolution committee: %v", i, err)
		return nil
	}

	// Decrypting the message M[k]
	zeroNonce := curve25519.Nonce{}
	mkMsg, err := curve25519.SymmetricDecrypt(epsKey, zeroNonce, msg.EncResM[k])
	if err != nil {
		log.Infof("dealer %d provided incorrect encryption of M[k] to resolution committee: %v", i, err)
		return nil
	}

	// Decoding of M[k]
	mk := VerificationMK{}
	err = msgpack.Decode(mkMsg, &mk)
	if err != nil {
		log.Infof("dealer %d provided incorrect encoding of M[k] to resolution committee: %v", i, err)
		return nil
	}

	// Verify Mk lists are the correct length
	if len(mk.R) != pub.N || len(mk.S) != pub.N {
		log.Infof("dealer %d provided incorrect M[k] - wrong list length", i)
		return nil
	}

	// Verify Mk contains valid shares
	for j := 0; j < n; j++ {
		valid, err := pedersen.VerifyCommitment(pub.VSSParams.PedersenParams, &msg.ComS[j][k+1], &mk.S[j], &mk.R[j])
		if err != nil {
			// TODO: a bit dirty, better error handling is important
			log.Errorf("dealer %d provided a commitment/share that make the verifcation returns an error: %v", i, err)
			return nil
		}
		if !valid {
			log.Infof("dealer %d provided incorrect shares for resolution (j=%d,k=%d)", i, j, k)
			return nil
		}
	}

	return &mk
}
