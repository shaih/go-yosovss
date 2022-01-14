package resharing

import (
	"fmt"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/shamir"
	"github.com/shaih/go-yosovss/primitives/vss"
)

// DealingMessage is the message dealers send during dealing round
// Notations below are for dealer i in [0,n-1]
type DealingMessage struct {
	_struct struct{}     `codec:",omitempty,omitemptyarray"`
	ComC    []feldman.VC `codec:"C"` // ComC[j] is a vector commitment to sigma_{i+1,j+1,l+1}, rho_{i+1,j+1,l+1}
	// for l in [0,n-1],
	// where sigma_{i+1,j+1,l+1} is the (j+1)-th share of sigma_{i+1,0,l+1}=sigma_{i+1,l+1},
	// where sigma_{i+1,l+1} for l in [0,n-1] is a sharing of sigma_{i+1}
	// and similar for rho with regards to the randomness r
	// comC[j] = sum_l sigma_{i+1,j,l+1} G_l + sum_l rho_{i+1,j,l+1} G_{l+n}
	// j in 0,...,n
	ComZ []pedersen.Commitment `codec:"Z"` // ComZ[l] = Z_{l+1} = sigma_{i+1,0,l} G + rho_{i+1,0,l+1} H
	// where G and H are the two fixed bases
	// l in 0,...,n-1
	ComZPrime []curve25519.PointXY `codec:"z"` // ComZPrime[l] = Z'_{l+1} = sigma_{i+1,0,l} G_l + rho_{i+1,0,l+1} H_l
	// l in 0,...,n-1
	DblDLEqProof DblDLEqProof `codec:"p"` // DblDLEqProof proves that ComZ and ComZPrime
	// commit to the same values
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
	SR []curve25519.Scalar // sigma_ij0,..., sigma_ijn-1, rho_ij0, ... (size = 2n)
}

// EpsK is the message for resolution committee member j
type EpsK struct {
	Eps []curve25519.Scalar // eps_{i,1,j+1},...,eps_{i,n,j+1}
	// TODO: not optimized as we could use a smaller modulus, but that's good enough for this implementation
}

// GenerateDealerSharesCommitments generate sigmaRho and comC for secret s and randomness r for dealer D_i
// where sigmaRho[j][l] is a (n+1)*2n matrix, see ComC in DealingMessage
//     sigmaRho[j][l]   = sigma_{i+1,j,l+1} for j in [0,n], l in [0,n-1]
// and sigmaRho[j][l+n] = rho_{i+1,j,l+1}   for j in [0,n], l in [0,n-1]
// sigma_{i+1,l+1} = sigma_{i+1,0,l+1} (for l in [0,n-1]) is a sharing of s
// same for rho
func GenerateDealerSharesCommitments(
	vssParams *vss.Params, vcParams *feldman.VCParams, s *curve25519.Scalar, r *curve25519.Scalar,
) (
	sigmaRho [][]curve25519.Scalar, comC []feldman.VC, err error,
) {
	n := vssParams.N
	t := vssParams.D + 1

	// Generate sigma
	sigma, err := genSigmaOrRho(s, t, n)
	if err != nil {
		return nil, nil, err
	}

	// Generate rho
	rho, err := genSigmaOrRho(r, t, n)
	if err != nil {
		return nil, nil, err
	}

	// Concatenate to obtain sigmaRho
	sigmaRho = make([][]curve25519.Scalar, n+1)
	for j := 0; j <= n; j++ {
		sigmaRho[j] = make([]curve25519.Scalar, 2*n)
		copy(sigmaRho[j][0:n], sigma[j])
		copy(sigmaRho[j][n:2*n], rho[j])
	}

	// Commitment
	comC = make([]feldman.VC, n+1)
	for j := 0; j <= n; j++ {
		cj, err := curve25519.MultiMultPointXYScalar(vcParams.Bases, sigmaRho[j])
		if err != nil {
			return nil, nil, err
		}
		comC[j] = *cj
	}

	return sigmaRho, comC, nil
}

// genSigmaOrRho generates the matrix sigma or rho as defined in GenerateDealerSharesCommitments
func genSigmaOrRho(s *curve25519.Scalar, t int, n int) (
	sigma [][]curve25519.Scalar, err error) {

	// First-level sharing
	// shares0[l] = sigma_{i+1,l+1} = sigma_{i+1,0,l+1} for
	shares0, err := shamir.GenerateShares(shamir.Message(*s), t, n)
	if err != nil {
		return nil, err
	}

	// Second-level sharing
	// shares[l][j] = sigma_{i+1,j+1,l+1}
	shares := make([][]shamir.Share, n)
	for l := 0; l < n; l++ {
		shares[l], err = shamir.GenerateShares(shamir.Message(shares0[l].S), t, n)
		if err != nil {
			return nil, err
		}
	}

	// Reorganize the shares into sigma
	sigma = make([][]curve25519.Scalar, n+1)
	for j := 0; j <= n; j++ {
		sigma[j] = make([]curve25519.Scalar, n+1)
	}
	// handle j=0
	for l := 0; l < n; l++ {
		sigma[0][l] = shares0[l].S
	}
	// handle j>0, i.e., sigma[j][l] = shares[l][j-1]
	for l := 0; l < n; l++ {
		for j := 1; j < n+1; j++ {
			sigma[j][l] = shares[l][j-1].S
		}
	}
	return sigma, nil
}

func genComZComZPrimeProof(n int, vcParams *feldman.VCParams, sigmaRho [][]curve25519.Scalar) (
	comZ []pedersen.Commitment, comZPrime []curve25519.PointXY, proof DblDLEqProof, err error,
) {

	comZ = make([]pedersen.Commitment, n)
	comZPrime = make([]curve25519.PointXY, n)

	for l := 0; l < n; l++ {
		zl, err := curve25519.DoubleMultBaseGHPointXYScalar(
			&sigmaRho[0][l], &sigmaRho[0][l+n],
		)
		if err != nil {
			return nil, nil, DblDLEqProof{}, err
		}
		comZ[l] = *zl

		zlPrime, err := curve25519.MultiMultPointXYScalar(
			[]curve25519.PointXY{vcParams.Bases[l], vcParams.Bases[n+l]},
			[]curve25519.Scalar{sigmaRho[0][l], sigmaRho[0][l+n]},
		)
		if err != nil {
			return nil, nil, DblDLEqProof{}, err
		}
		comZPrime[l] = *zlPrime
	}

	proof, err = DblDLEqProve(
		DblDLEqStatement{
			G:      vcParams.Bases[:n],
			H:      vcParams.Bases[n:],
			Z:      comZ,
			ZPrime: comZPrime,
		},
		DblDLEqWitness{
			X: sigmaRho[0][:n],
			Y: sigmaRho[0][n:],
		},
	)

	return
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

	sigmaRho, comC, err := GenerateDealerSharesCommitments(&pub.VSSParams, &pub.VCParams,
		&prv.Share.S, &prv.Share.R)
	if err != nil {
		return nil, fmt.Errorf("error while generating shares commitments: %w", err)
	}
	msg.ComC = comC

	msg.ComZ, msg.ComZPrime, msg.DblDLEqProof, err = genComZComZPrimeProof(pub.N, &pub.VCParams, sigmaRho)
	if err != nil {
		return nil, fmt.Errorf("error while generating Z/Z'/proof: %w", err)
	}

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
		mj := VerificationMJ{SR: sigmaRho[j+1]}

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
