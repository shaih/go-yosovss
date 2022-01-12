package auditor

import (
	"fmt"
	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/shaih/go-yosovss/primitives/shamir"
	"github.com/shaih/go-yosovss/primitives/vss"
)

// DealingMessage is the message dealers send during dealing round
// Notations below are for dealer i in [0,n-1]
type DealingMessage struct {
	_struct struct{}     `codec:",omitempty,omitemptyarray"`
	ComC    []feldman.VC `codec:"C"` // ComC[j] is a vector commitment to sigma_{i+1,j+1,l} for l in [0,n],
	// where sigma_{i+1,j+1,l} is the (j+1)-th share of sigma_{i+1,0,l}=sigma_{i+1,l},
	// where sigma_{i+1,l} for l in [1,n] is a sharing of sigma_{i+1}
	// and sigma_{i+1,0} is a random value
	// j in 0,...,n-1
	EncVerM []curve25519.Ciphertext `codec:"V"` // EncVerM[j] is an encryption under the verification
	// committee member j's key of message M[j] (type VerificationMJ)
	EncResM []curve25519.SymmetricCiphertext `codec:"R"` // EncResM[j] is a symmetric encryption of M[j]
	// under a fresh symmetric key K generated as follows:
	// generate a random scalar eps_{j+1} that is secret-shared into eps_{j+1,1},...,eps_{j+1,n}
	// K = HKDF(eps_{j+1})
	// j in 0,...,n-1
	EncEpsK []curve25519.Ciphertext `codec:"e"` // EncEpsK[j] is an encryption under the resolution
	// committee member j's key of message EpsK described below
	// j in 0,...,n-1
	HashEps [][][HashLength]byte `codec:"h"` // HashEps[j][j] is the hash of eps_{j+1,j+1}
	// j,j in 0,...,n-1
}

// VerificationMJ is the message M[j] for verification committee member j+1
type VerificationMJ struct {
	S []curve25519.Scalar // sigma_ij0,..., sigma_ijn
}

// EpsK is the message for resolution committee member j
type EpsK struct {
	Eps []curve25519.Scalar // eps_{i,1,j+1},...,eps_{i,n,j+1}
	// TODO: not optimized as we could use a smaller modulus, but that's good enough for this implementation
}

// GenerateDealerSharesCommitments generate sigma and comC and sigma for secret s for dealer D_i
// where sigma[j][l] = sigma_{i+1,j,l} is a (n+1)*(n+1) matrix, see ComC in DealingMessage
func GenerateDealerSharesCommitments(
	vssParams *vss.Params, vcParams *feldman.VCParams, s *curve25519.Scalar,
) (
	sigma [][]curve25519.Scalar, comC []feldman.VC, err error,
) {
	n := vssParams.N
	t := vssParams.D + 1

	// First-level sharing
	// shares0[l] = sigma_{i+1,l+1} = sigma_{i+1,0,l+1} for
	shares0, err := shamir.GenerateShares(shamir.Message(*s), t, n)
	if err != nil {
		return nil, nil, err
	}

	// sigma0 = sigma_{i+1,0} = a random value
	sigma0 := curve25519.RandomScalar()

	// Second-level sharing
	// shares[l][j] = sigma_{i+1,j+1,l}
	shares := make([][]shamir.Share, n+1)
	//   for l=0, shares[0][j] = sigma_{i,j+1,0} = shares (in j) of sigma0
	shares[0], err = shamir.GenerateShares(shamir.Message(*sigma0), t, n)
	if err != nil {
		return nil, nil, err
	}
	//   for l>0,
	for l := 1; l < n+1; l++ {
		shares[l], err = shamir.GenerateShares(shamir.Message(shares0[l-1].S), t, n)
		if err != nil {
			return nil, nil, err
		}
	}

	// Reorganize the shares into sigma
	sigma = make([][]curve25519.Scalar, n+1)
	for j := 0; j <= n; j++ {
		sigma[j] = make([]curve25519.Scalar, n+1)
	}
	// handle j=0,l=0, i.e., sigma[0][0]
	sigma[0][0] = shares0[0].S
	// handle j=0,l>0
	for l := 1; l < n+1; l++ {
		sigma[0][l] = shares0[l-1].S
	}
	// handle j>0, i.e., sigma[j][l] = shares[l][j-1]
	for l := 0; l < n+1; l++ {
		for j := 1; j < n+1; j++ {
			sigma[j][l] = shares[l][j-1].S
		}
	}

	// Commitment
	comC = make([]feldman.VC, n)
	for j := 0; j < n; j++ {
		cj, err := curve25519.MultiMultPointXYScalar(vcParams.Bases, sigma[j+1])
		if err != nil {
			return nil, nil, err
		}
		comC[j] = *cj
	}

	return sigma, comC, nil
}

// PerformDealing executes what a dealer does in the dealing round
// and returns the message it should broadcast
func PerformDealing(
	pub *PublicInput,
	prv *PrivateInput,
	dbg *PartyDebugParams,
) (*DealingMessage, error) {
	msg := &DealingMessage{
		EncVerM: make([]curve25519.Ciphertext, pub.N),
		EncResM: make([]curve25519.SymmetricCiphertext, pub.N),
		EncEpsK: make([]curve25519.Ciphertext, pub.N),
	}

	sigma, comC, err := GenerateDealerSharesCommitments(&pub.VSSParams, &pub.VCParams, &prv.Share.S)
	if err != nil {
		return nil, fmt.Errorf("error while generating shares commitments: %w", err)
	}
	msg.ComC = comC

	if len(pub.Committees.Ver) != pub.N {
		return nil, fmt.Errorf("invalid committee length")
	}

	// Generate keys and shares for resolution committee (future broadcast)
	var epsK []EpsK
	var epsKeys []curve25519.Key
	if !dbg.SkipDealingFutureBroadcast {
		epsKeys, epsK, msg.HashEps, err = GenerateAllEps(pub.N, pub.T)
		if err != nil {
			return nil, err
		}
	} else {
		msg.HashEps = [][][HashLength]byte{} // just to please go-codec
	}

	// Encryption for verification committee and resolution committee
	for j := 0; j < pub.N; j++ {
		// Compute M[j]
		mj := VerificationMJ{S: sigma[j+1]}

		mjMsg := msgpack.Encode(mj)

		// Encrypt M[j] for the verification member j+1
		msg.EncVerM[j], err = curve25519.Encrypt(pub.EncPKs[pub.Committees.Ver[j]], mjMsg)
		if err != nil {
			return nil, err
		}

		if !dbg.SkipDealingFutureBroadcast {
			// Encrypt M[j] for resolution / future broadcast
			// Use a zero nonce as the key is fresh
			zeroNonce := curve25519.Nonce{}
			msg.EncResM[j], err = curve25519.SymmetricEncrypt(epsKeys[j], zeroNonce, mjMsg)
			if err != nil {
				return nil, err
			}
		} else {
			msg.EncResM[j] = curve25519.SymmetricCiphertext{} // just to please go-codec
		}
	}

	// Encrypt epsK for each resolution committee member
	for k := 0; k < pub.N; k++ {
		if !dbg.SkipDealingFutureBroadcast {
			msg.EncEpsK[k], err = curve25519.Encrypt(pub.EncPKs[pub.Committees.Res[k]], msgpack.Encode(epsK[k]))
			if err != nil {
				return nil, err
			}
		} else {
			msg.EncEpsK[k] = curve25519.Ciphertext{} // just to please go-codec
		}
	}

	return msg, nil
}
