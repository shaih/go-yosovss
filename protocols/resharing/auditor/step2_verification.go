package auditor

import (
	"fmt"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	log "github.com/sirupsen/logrus"
)

// VerSentShares for verification committee member j+1 and holding committeee member l+1
// contains the shares sigma_{i+1,j+1,l}, for i in [0,n-1] (i+1 corresponding to the dealer)
// with nil for every dealer i that has incorrect shares
type VerSentShares struct {
	S []*curve25519.Scalar // sigma_{1,j+1,l+1},..., sigma_{n,j+1,l+1}
}

// VerificationMessage is the message verification committee members send during verification round
// Below we assume the committee member is j
type VerificationMessage struct {
	_struct    struct{}                `codec:",omitempty,omitemptyarray"`
	Complaints []bool                  `codec:"C"` // Complaints[i] == true iff complaint against dealer i+1
	EncShares  []curve25519.Ciphertext `codec:"S"` // EncShares[l] contains an encryption of VerSentShare
	// for new holding committee member l+1 (type = VerSentShares)
	// TODO: missing additional commitments and proofs
}

// PerformVerification executes what a verification committee member j does in the dealing round
// and returns the messages/complaints that it should broadcast. It decrypts all the shares sent
// to its index (i.e. j), and checks them.
// If the check succeeds then the verifier forwards the shares-of-shares to the next holding
// committee. Else is zeros-out the shares from that dealer and adds a complaint about it.
// j is in [0,n-1]
func PerformVerification(
	pub *PublicInput, prv *PrivateInput, j int,
	dealingMessages []DealingMessage,
	dbg *PartyDebugParams,
) (
	*VerificationMessage, error,
) {

	var err error

	myLog := log.WithFields(log.Fields{
		"party":     prv.ID,
		"committee": "verification",
		"l":         j,
	})

	msg := &VerificationMessage{
		EncShares:  make([]curve25519.Ciphertext, pub.N),
		Complaints: make([]bool, pub.N),
	}

	// Allocate verSentShares, the values to be encrypted in msg.EncShares
	// verSentShares[l] contains the shares sigma_{i+1,l+1,l+1} for i in [0,n-1]
	verSentShares := make([]VerSentShares, pub.N)

	for l := 0; l < pub.N; l++ {
		verSentShares[l] = VerSentShares{
			S: make([]*curve25519.Scalar, pub.N),
		}
	}

	for i := 0; i < pub.N; i++ {
		// Fill in verSentShares[l].S[i] for all l
		// And issue a complaint against dealer i if something goes wrong

		// Get the message mj
		mj := getMJ(pub, prv, j, dealingMessages, i, myLog)
		if mj == nil {
			// complain if mj cannot be recovered
			msg.Complaints[i] = true
			continue
		}

		// FIXME: we need more tests to check for example that comS is correct length
		// FIXME: but this can be done at the receiving end as its public, not here

		// Verify shares
		if !dbg.SkipVerificationVerifyShare {
			err := VerifyMJ(&pub.VCParams, &dealingMessages[i].ComC[j], mj)
			if err != nil {
				// invalid dealer
				msg.Complaints[i] = true
				myLog.Infof("complain against dealer %d: invalid Cij: %v", i, err)
				break
			}
		}

		// Propagate the correct shares
		for l := 0; l < pub.N; l++ {
			verSentShares[l].S[i] = &mj.S[l+1]
		}
	}

	for i := 0; i < pub.N; i++ {
		// Make nil the shares of dealers we complained about
		if msg.Complaints[i] {
			for l := 0; l < pub.N; l++ {
				verSentShares[l].S[i] = nil
			}
		}
	}

	// Encrypt all the verSentShares
	for l, nextHolder := range pub.Committees.Next {
		msg.EncShares[l], err = curve25519.Encrypt(pub.EncPKs[nextHolder], msgpack.Encode(verSentShares[l]))
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

func VerifyMJ(vcParams *feldman.VCParams, comCIJ *feldman.VC, mj *VerificationMJ) error {
	tmp, err := curve25519.MultiMultPointXYScalar(vcParams.Bases, mj.S)
	if err != nil {
		return fmt.Errorf("verify C_ij failed: %w", err)
	}
	if curve25519.PointXYEqual(comCIJ, tmp) {
		return fmt.Errorf("verify C_ij failed because point non-equal")
	}
	return nil
}

// getMJ decrypts and decode message MK sent by dealer i to verifier j
// it checks validity of the message
// returns nil if a complain must be done
func getMJ(
	pub *PublicInput, prv *PrivateInput, j int,
	dealingMessages []DealingMessage, i int,
	myLog *log.Entry,
) (mk *VerificationMJ) {

	// Decrypt and decode M_k
	b, err := curve25519.Decrypt(pub.EncPKs[prv.ID], prv.EncSK, dealingMessages[i].EncVerM[j])
	if err != nil {
		// invalid dealer
		myLog.Infof("complain against dealer %d: %v", i, err)
		return nil
	}

	mk = &VerificationMJ{}
	err = msgpack.Decode(b, mk)
	if err != nil {
		// invalid dealer
		myLog.Infof("complain against dealer %d: %v", i, err)
		return nil
	}

	// Verify Mk lists are the correct length
	if len(mk.S) != pub.N+1 {
		// invalid dealer
		myLog.Infof("complain against dealer %d: R or S of incorrect length", i)
		return nil
	}

	return mk
}
