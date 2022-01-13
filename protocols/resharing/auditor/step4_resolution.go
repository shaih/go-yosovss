package auditor

import (
	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	log "github.com/sirupsen/logrus"
)

type TripleIJL struct {
	i int // corresponding to dealer D_i, i in [0,n-1]
	j int // corresponding to verifier V_j, j in [0,n-1]
	l int // corresponding to new holder P_{l+1} / 0, l in [0,n]
}

// CheckDealingMessages check if msg is valid
// If not, print an info log message
func CheckDealingMessages(pub *PublicInput, msg DealingMessage, i int, dbg *PartyDebugParams) bool {
	// TODO: we actually may need to do that before ResolveComplaints
	// TODO" tests may not be sufficient

	n := pub.N

	// Check dealer message are valid and disqualify if invalid
	if (!dbg.SkipDealingFutureBroadcast && len(msg.EncResM) != n) ||
		(!dbg.SkipDealingFutureBroadcast && len(msg.HashEps) != n) ||
		len(msg.EncVerM) != n ||
		len(msg.ComC) != n+1 {
		log.Infof("dealer %d disqualified as it sent incorrect message", i)
		return false
	}

	// TODO FIXME: we need to check that the points in ComC is valid too
	// and most likely different than point at infinity as libsodium does not like point at infinity
	// for exponentiation
	// FIXME: I think it's not necessary as we verify NIZK

	if !dbg.SkipDealingFutureBroadcast {
		for k := 0; k < n; k++ {
			if len(msg.HashEps) != n {
				log.Infof("dealer %d disqualified as it sent incorrect message", i)
				return false
			}
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
	dbg *PartyDebugParams,
) (
	resolvedSharesSR map[TripleIJL]curve25519.Scalar,
	disqualifiedDealers map[int]bool,
	err error,
) {
	n := pub.N

	resolvedSharesSR = map[TripleIJL]curve25519.Scalar{}

	disqualifiedDealers = map[int]bool{}

	for i := 0; i < n; i++ {
		if !CheckDealingMessages(pub, dealingMessages[i], i, dbg) {
			disqualifiedDealers[i] = true
			continue
		}

		for j := 0; j < n; j++ {
			if len(verificationMessages[j].Complaints) == n && verificationMessages[j].Complaints[i] {
				// Vj complained against dealer i

				// Recovering all epsShares (eps_{i+1,j+1,k+1}) we can
				epsShares := make([]*curve25519.Scalar, n)
				for k := 0; k < n; k++ {
					epsIJK, ok := resolutionMessages[k].EpsShares[PairIJ{i, j}]
					if ok {
						epsShares[k] = &epsIJK
					}
				}

				// Get the M[j] by reconstructing the key and decrypting it
				// also verify shares are valid
				mj := getAndVerifyResolutionMJ(pub, &dealingMessages[i], epsShares, i, j)
				if mj == nil {
					// impossible to get a correct MK, reject
					disqualifiedDealers[i] = true
					break
				}

				// Store the shares
				for l := 0; l < 2*n; l++ {
					resolvedSharesSR[TripleIJL{i, j, l}] = mj.SR[l]
				}
			}
		}
	}

	return
}

func getAndVerifyResolutionMJ(
	pub *PublicInput,
	msg *DealingMessage,
	epsShares []*curve25519.Scalar,
	i int,
	j int,
) *VerificationMJ {
	n := pub.N

	// Reconstructing the key
	epsKey, err := ReconstructEpsKey(n, pub.T, epsShares, msg.HashEps[j])
	if err != nil {
		log.Infof("dealer %d provided incorrect shares to resolution committee: %v", i, err)
		return nil
	}

	// Decrypting the message M[j]
	zeroNonce := curve25519.Nonce{}
	mkMsg, err := curve25519.SymmetricDecrypt(epsKey, zeroNonce, msg.EncResM[j])
	if err != nil {
		log.Infof("dealer %d provided incorrect encryption of M[j] to resolution committee: %v", i, err)
		return nil
	}

	// Decoding of M[j]
	mj := VerificationMJ{}
	err = msgpack.Decode(mkMsg, &mj)
	if err != nil {
		log.Infof("dealer %d provided incorrect encoding of M[j] to resolution committee: %v", i, err)
		return nil
	}

	// Verify Mj lists are the correct length
	if len(mj.SR) != pub.N*2 {
		log.Infof("dealer %d provided incorrect M[j] - wrong list length", i)
		return nil
	}

	// Verify Mj contains valid shares
	err = VerifyMJ(&pub.VCParams, &msg.ComC[j+1], &mj)
	if err != nil {
		// invalid dealer
		log.Infof("dealer %d provided a commitment/share that make the verifcation returns an error: %v",
			i, err)
		return nil
	}

	return &mj
}
