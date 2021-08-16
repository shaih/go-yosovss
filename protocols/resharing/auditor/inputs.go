package auditor

import (
	"fmt"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
)

// PublicInput contain the public common inputs that are used in the resharing protocol
// Note that to simplify implementation we assume it contains all the committees
// In the real-world, it would not and additional logic should be used for committee selection
type PublicInput struct {
	EncPKs                   []curve25519.PublicKey     // encryption public keys
	SigPKs                   []curve25519.PublicSignKey // signature public keys - NOT USED
	VSSParams                vss.Params                 // parameters for the VSS
	T                        int                        // max number of malicious parties (=VSSParams.D)
	N                        int                        // size of the committee (=VSSParams.N)
	AuditMinWitInvalidDealer int                        // an invalid dealer will have at least this number m' of valid witnesses (= parameter m')
	AuditMaxFalseWitDealer   int                        // when this number of false witnesses if reached, the dealer is considered valid (= parameter m)
	Committees               Committees                 // list of committees
	Commitments              []pedersen.Commitment      // list of the N+1 commitments to the secret and each of the secret shares
	// Note: Commitments[0] is the commitment to the secret,
	//       and Commitments[1] is the commitment to the first share of the first party
	// TODO: This is slightly less efficient than necessary, to have to comput commitments[0]
	//       but should not matter in the grand scheme of things
}

type PrivateInput struct {
	BC    communication.BroadcastChannel
	EncSK curve25519.PrivateKey
	SigSK curve25519.PrivateSignKey
	Share *vss.Share // if the party is not a dealer (i.e., not in the original holding committe), it's nil
	Id    int
}

// checkInputs performs basic checks on the inputs to catch most common errors
func checkInputs(pub *PublicInput, prv *PrivateInput) error {
	if pub.T >= pub.N {
		return fmt.Errorf("T must be < N")
	}
	if len(pub.Commitments) != pub.N+1 {
		return fmt.Errorf("len of commitments must be N+1")
	}
	// FIXME: add more checks
	return nil
}
