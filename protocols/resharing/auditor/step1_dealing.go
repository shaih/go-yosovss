package auditor

import (
	"fmt"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
)

// DealingMessage is the message dealers send during dealing round
type DealingMessage struct {
	_struct struct{}                `codec:",omitempty,omitemptyarray"`
	ComS    [][]pedersen.Commitment `codec:"S"` // n x (n+1) matrix where
	// (com[j][0])_j=0,...,n-1 are commitments to first-level shares sigma_{j+1} of the secret s of the dealer
	// and for each j, com[j][k] for k=1,...,n are commitments to the shares sigma_{j+1,k} of the share sigma_{j+1}
	EncVerM []curve25519.Ciphertext `codec:"V"` // EncVerM[k] is an encryption under the verification
	// key committee of message M[k] (type VerificationMK)
	// TODO future broadcast
}

// VerificationMK is the message M[k] for verification committee member k
type VerificationMK struct {
	S []curve25519.Scalar // sigma_1k,..., sigma_nk
	R []curve25519.Scalar // rho_1k, ..., rho_nk
}

func GenerateDealerSharesCommitments(
	vssParams *vss.Params, s, r *curve25519.Scalar,
) (
	shares [][]vss.Share, comS [][]pedersen.Commitment, err error,
) {
    comS = make([][]pedersen.Commitment, vssParams.N)

	// First-level sharing
	// commitments are not needed as they're recomputed anyway by second level
	// TODO this is not optimal
	shares0, _, err := vss.FixedRShare(vssParams, *s, *r)
	if err != nil {
		return nil, nil, err
	}

	// Second-level sharing
	shares = make([][]vss.Share, vssParams.N)
	for j := 0; j < vssParams.N; j++ {
		shares[j], comS[j], err = vss.FixedRShare(vssParams, shares0[j].S, shares0[j].R)
		if err != nil {
			return nil, nil, err
		}
	}

	return shares, comS, nil
}

// PerformDealing executes what a dealer does in the dealing round
// and returns the message it should broadcast
func PerformDealing(pub *PublicInput, prv *PrivateInput) (*DealingMessage, error) {
	msg := &DealingMessage{
		EncVerM: make([]curve25519.Ciphertext, pub.N),
	}

	shares, comS, err := GenerateDealerSharesCommitments(&pub.VSSParams, &prv.Share.S, &prv.Share.R)
	if err != nil {
		return nil, err
	}
	msg.ComS = comS

	if len(pub.Committees.Ver) != pub.N {
		return nil, fmt.Errorf("invalid committe length")
	}

	// Encryption for verification committee
	for k, verId := range pub.Committees.Ver {
		mk := VerificationMK{
			S: make([]curve25519.Scalar, pub.N),
			R: make([]curve25519.Scalar, pub.N),
		}
		for j := 0; j < pub.N; j++ {
			mk.S[j] = shares[j][k].S
			mk.R[j] = shares[j][k].R
		}
		msg.EncVerM[k], err = curve25519.Encrypt(pub.EncPKs[verId], msgpack.Encode(mk))
	}

	return msg, nil
}
