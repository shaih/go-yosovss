package auditor

import (
	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	log "github.com/sirupsen/logrus"
)

// PairIK is a pair of two integers i and k
// i,k in 0,...,n-1 and represent a dealer i and a verification member committee k (Vk) respectively
type PairIK struct {
	i, k int
}

// ResolutionMessage is the message resolution committee members send during resolution round
// Below we assume the committee member is l
type ResolutionMessage struct {
	_struct   struct{}                     `codec:",omitempty,omitemptyarray"`
	EpsShares map[PairIK]curve25519.Scalar `codec:"E"` // EpsShares[(i,k)] = eps_{k+1,l+1} for dealer i if there was a complaint from
}

// PerformResolution executes what a resolution committee member l does in the resolution round
// and returns the message it should broadcast
// l is the index of the party in the verification committee
func PerformResolution(
	pub *PublicInput, prv *PrivateInput, l int,
	dealingMessages []DealingMessage, verificationMessages []VerificationMessage,
) (
	*ResolutionMessage, error,
) {
	myLog := log.WithFields(log.Fields{
		"party":     prv.Id,
		"committee": "resolution",
		"l":         l,
	})

	n := pub.N

	msg := ResolutionMessage{
		EpsShares: map[PairIK]curve25519.Scalar{},
	}

	for i := 0; i < n; i++ {
		var epsL *EpsL = nil

		for k := 0; k < n; k++ {
			if len(verificationMessages[k].Complaints) == n && verificationMessages[k].Complaints[i] {
				// Vk complained against dealer i
				myLog.Infof("verification committee member k=%d complaints against dealer %d", k, i)

				// Decrypt and decode epsL if not yet decrypted
				if epsL == nil {
					epsL = DecryptEpsL(pub, prv, l, dealingMessages, i, myLog)
					// If it fails, stops with this dealer
					if epsL == nil {
						break
					}
				}

				// Broadcast eps_{k+1,l+1}
				msg.EpsShares[PairIK{i, k}] = epsL.Eps[k]
			}
		}
	}

	return &msg, nil
}

func DecryptEpsL(
	pub *PublicInput,
	prv *PrivateInput,
	l int,
	dealingMessages []DealingMessage,
	i int,
	myLog *log.Entry,
) *EpsL {
	b, err := curve25519.Decrypt(pub.EncPKs[prv.Id], prv.EncSK, dealingMessages[i].EncEpsL[l])
	if err != nil {
		// invalid dealer
		myLog.Infof("dealer %d did not encrypt properly epsL[%d]: %v", i, l, err)
		return nil
	}

	var epsL EpsL
	err = msgpack.Decode(b, &epsL)
	if err != nil {
		// invalid dealer
		myLog.Infof("dealer %d did not encode properly epsL[%d]: %v", i, l, err)
		return nil
	}

	return &epsL
}
