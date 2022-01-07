package auditor

import (
	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	log "github.com/sirupsen/logrus"
)

// PairIJ is a pair of two integers i and j
// i,j in 0,...,n-1 and represent a dealer i and a verification member committee j (Vk) respectively
type PairIJ struct {
	i, j int
}

// ResolutionMessage is the message resolution committee members send during resolution round
// Below we assume the committee member is l
type ResolutionMessage struct {
	_struct   struct{}                     `codec:",omitempty,omitemptyarray"`
	EpsShares map[PairIJ]curve25519.Scalar `codec:"E"`
	// EpsShares[(i,j)] = eps_{j+1,l+1} for dealer i if there was a complaint from
}

// PerformResolution implements the role of party ell in the resolution (future
// broadcast) committee, and returns the message that it should broadcast.
// ell is the index of the party in the resolution committee
func PerformResolution(
	pub *PublicInput, prv *PrivateInput, l int,
	dealingMessages []DealingMessage, verificationMessages []VerificationMessage,
) (
	*ResolutionMessage, error,
) {
	myLog := log.WithFields(log.Fields{
		"party":     prv.ID,
		"committee": "resolution",
		"l":         l,
	})

	n := pub.N

	msg := ResolutionMessage{
		EpsShares: map[PairIJ]curve25519.Scalar{},
	}

	epsLI := make([]*EpsK, n) // epsLI[i] is non-nil when decrypted once

	// We order the loops this way to optimize memory
	// accessing verificationMessages[j] by order of j
	// It is unclear that it matters though...
	// Most likely the decoding of the messages cost already much more...

	for k := 0; k < n; k++ { // message sent by party j in verification cmte
		if len(verificationMessages[k].Complaints) != n {
			// the verifier j is invalid
			continue
		}
		for i := 0; i < n; i++ {
			if verificationMessages[k].Complaints[i] {
				// Verifier j complained against dealer i
				myLog.Infof("verification committee member j=%d complaints against dealer %d", k, i)

				// Decrypt and decode epsL if not yet decrypted
				if epsLI[i] == nil {
					epsLI[i] = DecryptEpsK(pub, prv, l, dealingMessages, i, myLog)
					// If it fails, stops with this dealer
					if epsLI[i] == nil {
						break
					}
				}

				// Broadcast i'th share according to j (eps_{j+1,l+1})
				msg.EpsShares[PairIJ{i, k}] = epsLI[i].Eps[k]
			}
		}
	}

	return &msg, nil
}

func DecryptEpsK(
	pub *PublicInput,
	prv *PrivateInput,
	k int,
	dealingMessages []DealingMessage,
	i int,
	myLog *log.Entry,
) *EpsK {
	b, err := curve25519.Decrypt(pub.EncPKs[prv.ID], prv.EncSK, dealingMessages[i].EncEpsK[k])
	if err != nil {
		// invalid dealer
		myLog.Infof("dealer %d did not encrypt properly epsL[%d]: %v", i, k, err)
		return nil
	}

	var epsL EpsK
	err = msgpack.Decode(b, &epsL)
	if err != nil {
		// invalid dealer
		myLog.Infof("dealer %d did not encode properly epsL[%d]: %v", i, k, err)
		return nil
	}

	return &epsL
}
