package auditor

import (
	"fmt"
	"github.com/shaih/go-yosovss/msgpack"
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
	// committee member k's key of message M[k] (type VerificationMK)
	EncResM []curve25519.SymmetricCiphertext `codec:"R"` // EncResM[k] is a symmetric encryption of M[k]
	// under a fresh symmetric key K generated as follows:
	// generate a random scalar eps_{k+1} that is secret-shared into eps_{k+1,1},...,eps_{k+1,n}
	// K = HKDF(eps_k+1)
	// k in 0,...,n-1
	EncEpsL []curve25519.Ciphertext `codec:"e"` // EncEpsL[l] is an encryption under the resolution
	// committee member l's key of message EpsL described below
	// l in 0,...,n-1
	HashEps [][][HashLength]byte `codec:"h"` // HashEps[k][l] is the hash of eps_{k,l+1}
	// k,l in 0,...,n-1
}

// VerificationMK is the message M[k] for verification committee member k
type VerificationMK struct {
	S []curve25519.Scalar // sigma_1k,..., sigma_nk
	R []curve25519.Scalar // rho_1k, ..., rho_nk
}

// EpsL is the message for resolution committee member l
type EpsL struct {
	Eps []curve25519.Scalar // eps_{1,l+1},...,eps_{n,l+1}
	// TODO: not optimized as we could use a smaller modulus, but that's good enough for this implementation
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
	shares0, _, err := vss.FixedRShare(vssParams, s, r)
	if err != nil {
		return nil, nil, err
	}

	// Second-level sharing
	shares = make([][]vss.Share, vssParams.N)
	for j := 0; j < vssParams.N; j++ {
		shares[j], comS[j], err = vss.FixedRShare(vssParams, &shares0[j].S, &shares0[j].R)
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
		EncResM: make([]curve25519.SymmetricCiphertext, pub.N),
		EncEpsL: make([]curve25519.Ciphertext, pub.N),
	}

	shares, comS, err := GenerateDealerSharesCommitments(&pub.VSSParams, &prv.Share.S, &prv.Share.R)
	if err != nil {
		return nil, err
	}
	msg.ComS = comS

	if len(pub.Committees.Ver) != pub.N {
		return nil, fmt.Errorf("invalid committe length")
	}

	// Generate keys and shares for resolution committee (future broadcast)
	var epsL []EpsL
	var epsKeys []curve25519.Key
	epsKeys, epsL, msg.HashEps, err = GenerateAllEps(pub.N, pub.T)
	if err != nil {
		return nil, err
	}

	// Encryption for verification committee and resolution committee
	for k := 0; k < pub.N; k++ {
		// Compute M[K]
		mk := ComputeMK(pub.N, shares, k)

		mkMsg := msgpack.Encode(mk)

		// Encrypt M[k] for the verification committee
		msg.EncVerM[k], err = curve25519.Encrypt(pub.EncPKs[pub.Committees.Ver[k]], mkMsg)

		// Encrypt M[k] for resolution / future broadcast
		// Use a zero nonce as the key is fresh
		zeroNonce := curve25519.Nonce{}
		msg.EncResM[k], err = curve25519.SymmetricEncrypt(epsKeys[k], zeroNonce, mkMsg)
	}

	// Encrypt epsL for each resolution committee member
	for l := 0; l < pub.N; l++ {
		msg.EncEpsL[l], err = curve25519.Encrypt(pub.EncPKs[pub.Committees.Res[l]], msgpack.Encode(epsL[l]))
	}

	return msg, nil
}

// ComputeMK computes the verification committee message M[k] see above
func ComputeMK(n int, shares [][]vss.Share, k int) VerificationMK {
	mk := VerificationMK{
		S: make([]curve25519.Scalar, n),
		R: make([]curve25519.Scalar, n),
	}
	for j := 0; j < n; j++ {
		mk.S[j] = shares[j][k].S
		mk.R[j] = shares[j][k].R
	}
	return mk
}
