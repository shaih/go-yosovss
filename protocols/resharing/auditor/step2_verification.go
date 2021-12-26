package auditor

import (
	"fmt"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/vss"
	log "github.com/sirupsen/logrus"
)

// VerSentShares for verification committee member k and holding committeee member j
// contains the shares sigma_{i,j,k} and rho_{i,j,k}, for i in [n] (i corresponding to the dealer)
// with nil for every dealer i that has incorrect shares
type VerSentShares struct {
	S []*curve25519.Scalar // sigma_1jk,..., sigma_njk
	R []*curve25519.Scalar // rho_1kk, ..., rho_njk
}

// VerificationMessage is the message verification committee members send during verification round
// Below we assume the committee member is k
type VerificationMessage struct {
	_struct    struct{}                `codec:",omitempty,omitemptyarray"`
	Complaints []bool                  `codec:"C"` // Complaints[i] == true iff complaint against dealer i
	EncShares  []curve25519.Ciphertext `codec:"S"` // EncShares[j] contains an encryption of VerSentShare
	// for  new holding committee member j (type = VerSentShares)
}

// PerformVerification executes what a verification committee member k does in the dealing round
// and returns the messages/complaints that it should broadcast. It decrypts all the shares sent
// to its index (i.e. k), and checks them.
// If the check succeeds then the verifier forwards the shares-of-shares to the next holding
// ommittee. Else is zeros-out the shares from that dealer and adds a complaint about it.
func PerformVerification(
	pub *PublicInput, prv *PrivateInput, k int,
	dealingMessages []DealingMessage,
	dbg *PartyDebugParams,
) (
	*VerificationMessage, error,
) {

	var err error

	myLog := log.WithFields(log.Fields{
		"party":     prv.Id,
		"committee": "verification",
		"k":         k,
	})

	msg := &VerificationMessage{
		EncShares:  make([]curve25519.Ciphertext, pub.N),
		Complaints: make([]bool, pub.N),
	}

	// Allocate verSentShares, the values to be encrypted in msg.EncShares
	// verSentShares[j] contains the shares sigma_ijk
	verSentShares := make([]VerSentShares, pub.N)

	for j := 0; j < pub.N; j++ {
		verSentShares[j] = VerSentShares{
			S: make([]*curve25519.Scalar, pub.N),
			R: make([]*curve25519.Scalar, pub.N),
		}
	}

	// Shares received by the verification committee member k
	// have index k+1
	shareIndex := k + 1
	shareIndexScalar := curve25519.GetScalar(uint64(shareIndex))

	for i := 0; i < pub.N; i++ {
		// Fill in verSentShares[j].S[i] for all j
		// And issue a complain for dealer i if something goes wrong

		// Get the message mk
		mk := getMK(pub, prv, k, dealingMessages, i, myLog)
		if mk == nil {
			// complain if mk cannot be recovered
			msg.Complaints[i] = true
			continue
		}

		// FIXME: we need more tests to check for example that comS is correct length
		// FIXME: but this can be done at the receiving end as its public, not here

		// Verify shares
		for j := 0; j < pub.N; j++ {
			if !dbg.SkipVerificationVerifyShare {
				valid, err := vss.VerifyShare(
					&pub.VSSParams,
					&vss.Share{
						Index:       shareIndex,
						IndexScalar: *shareIndexScalar,
						S:           mk.S[j],
						R:           mk.R[j],
					},
					dealingMessages[i].ComS[j],
				)
				if err != nil {
					return nil, fmt.Errorf("verify share failed: %w", err)
				}
				if !valid {
					// invalid dealer
					msg.Complaints[i] = true
					myLog.Infof("complain against dealer %d: R or S of incorrect length", i)
					break
				}
			}

			// Propagate the correct shares
			verSentShares[j].S[i] = &mk.S[j]
			verSentShares[j].R[i] = &mk.R[j]
		}
	}

	for i := 0; i < pub.N; i++ {
		// Make nil the shares of dealers we complained about
		if msg.Complaints[i] {
			for j := 0; j < pub.N; j++ {
				verSentShares[j].S[i] = nil
				verSentShares[j].R[i] = nil
			}
		}
	}

	// Encrypt all the verSentShares
	for j, nextHolder := range pub.Committees.Next {
		msg.EncShares[j], err = curve25519.Encrypt(pub.EncPKs[nextHolder], msgpack.Encode(verSentShares[j]))
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// getMK decrypts and decode message MK sent by dealer i to verifier k
// it checks validity of the message
// returns nil if a complain must be done
func getMK(
	pub *PublicInput, prv *PrivateInput, k int,
	dealingMessages []DealingMessage, i int,
	myLog *log.Entry,
) (mk *VerificationMK) {

	// Decrypt and decode M_k
	b, err := curve25519.Decrypt(pub.EncPKs[prv.Id], prv.EncSK, dealingMessages[i].EncVerM[k])
	if err != nil {
		// invalid dealer
		myLog.Infof("complain against dealer %d: %v", i, err)
		return nil
	}

	mk = &VerificationMK{}
	err = msgpack.Decode(b, mk)
	if err != nil {
		// invalid dealer
		myLog.Infof("complain against dealer %d: %v", i, err)
		return nil
	}

	// Verify Mk lists are the correct length
	if len(mk.R) != pub.N || len(mk.S) != pub.N {
		// invalid dealer
		myLog.Infof("complain against dealer %d: R or S of incorrect length", i)
		return nil
	}

	return mk
}
