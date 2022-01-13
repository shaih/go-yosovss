package auditor

import (
	"fmt"

	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
)

// PublicInput contain the public common inputs that are used in the resharing protocol
// Note that to simplify implementation we assume it contains all the committees
// In the real-world, it would not and additional logic should be used for committee selection
type PublicInput struct {
	VCParams    feldman.VCParams           // vector commitment params
	EncPKs      []curve25519.PublicKey     // encryption public keys
	SigPKs      []curve25519.PublicSignKey // signature public keys - NOT USED
	VSSParams   vss.Params                 // parameters for the VSS
	T           int                        // max number of malicious parties (=VSSParams.D)
	N           int                        // size of the committee (=VSSParams.N)
	Committees  Committees                 // list of committees
	Commitments []pedersen.Commitment      // list of N+1 Feldman commitments to the secret and the secret shared

	// Note: Commitments[0] is the commitment to the secret,
	//       and Commitments[i] is the commitment to the first share of the first party
	// TODO: This is slightly less efficient than necessary, to have to compute commitments[0]
	//       but should not matter in the grand scheme of things
}

// TODO IMPORTANT: contrary to the paper, we use Pedersen at the top level
// We don't transform in Feldman hence the Share *vss.Share

type PrivateInput struct {
	BC    communication.BroadcastChannel
	EncSK curve25519.PrivateKey
	SigSK curve25519.PrivateSignKey
	Share *vss.Share // if the party is not a dealer (i.e., not in the original holding committe), it's nil
	ID    int
}

// checkInputs performs basic checks on the inputs to catch most common errors
func checkInputs(pub *PublicInput, prv *PrivateInput) error {
	if pub.T >= pub.N {
		return fmt.Errorf("T must be < N")
	}
	if len(pub.VCParams.Bases) != pub.N*2 {
		return fmt.Errorf("len of bases must be N+1")
	}
	// FIXME: add more checks
	return nil
}
