package resharing

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/shamir"
	"golang.org/x/crypto/hkdf"
)

// File related to keys / shares for resolution committee / future braodcast
// denomiated by eps/epsilon in the paper
// See also step1_dealing.go for details, and structure DealingMessage

const (
	// HashLength is the length of hashes we use in bytes
	HashLength = 32
)

// GenerateAllEps generate all the epsKeys, epsL structures, and corresponding hashes
// for all resolution committee members
func GenerateAllEps(n int, t int) (epsKeys []curve25519.Key, epsK []EpsK, hashEps [][][HashLength]byte, err error) {
	// Initialization
	epsKeys = make([]curve25519.Key, n)
	epsK = make([]EpsK, n)
	hashEps = make([][][HashLength]byte, n)
	for k := 0; k < n; k++ {
		epsK[k].Eps = make([]curve25519.Scalar, n)
	}

	chacha20Key, err := curve25519.RandomChacha20Key()
	if err != nil {
		return nil, nil, nil, err
	}
	eps := curve25519.Scalar{}

	for j := 0; j < n; j++ {
		// Generate random secret seed eps for Vk
		curve25519.RandomScalarChacha20C(&eps, &chacha20Key, uint64(j))

		// Secret share it and derive the symmetric encryption key epsKey
		epsKey, epsShares, err := GenerateEpsKeyShares(n, t, &eps)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate eps keys for j=%d: %w", j, err)
		}

		epsKeys[j] = epsKey
		hashEps[j] = make([][HashLength]byte, n)
		for k := 0; k < n; k++ {
			hashEps[j][k] = sha256.Sum256(epsShares[k][:])
			epsK[k].Eps[j] = epsShares[k]
		}
	}
	return
}

// GenerateEpsKeyShares generates a fresh key for resolution/future broadcast as follows:
// secret share its input eps (that is supposed to be uniformly random) into epsShares
// and make the key epsKey be HKDF(eps) using KeyFromEps function
// d is the degree of Shamir's polynomial
func GenerateEpsKeyShares(
	n int,
	d int,
	eps *curve25519.Scalar,
) (
	epsKey curve25519.Key,
	epsShares []curve25519.Scalar,
	err error,
) {
	// Derive the symmetric encryption key from it
	epsKey, err = SymmetricKeyFromEps(eps)
	if err != nil {
		return [32]byte{}, nil, err
	}

	// Generate the shares of epsKey
	shares, err := shamir.GenerateShares(shamir.Message(*eps), d+1, n)
	if err != nil {
		return [32]byte{}, nil, err
	}

	// Conversion into a basic array
	epsShares = make([]curve25519.Scalar, n)
	for i := 0; i < n; i++ {
		epsShares[i] = shares[i].S
	}

	return epsKey, epsShares, nil
}

// SymmetricKeyFromEps converts the eps scalar that is shared into the symmetric key
// that is used to encrypt ciphertexts of M[j] for future broadcast
func SymmetricKeyFromEps(eps *curve25519.Scalar) (epsKey curve25519.Key, err error) {
	// TODO: normally we want some hardcoded salt there
	hkdf := hkdf.New(sha256.New, eps[:], nil, nil)

	// Extract the key epsKey from the secret eps
	_, err = io.ReadFull(hkdf, epsKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	return epsKey, nil
}

// ReconstructEpsKey takes as input an array of potential shares epsShares and the hash of the shares
// epsShares[i] is either nil (share not provided), the valid (i+1)-th share (i.e., matching hashEps[i]),
// or an invalid share
// If there are at least d+1 valid shares, ReconstructEpsKey reconstructs the epsKey and returns it
// otherwise it returns an error
func ReconstructEpsKey(
	n, d int,
	epsShares []*curve25519.Scalar,
	hashEps [][HashLength]byte,
) (
	epsKey curve25519.Key,
	err error,
) {
	// Find d+1 valid shares
	validShares := make([]shamir.Share, 0, d+1) // prepare an array of capacity d+1
	for i := 0; i < n && len(validShares) < d+1; i++ {
		if epsShares[i] == nil {
			continue // share not provided
		}
		if sha256.Sum256(epsShares[i][:]) == hashEps[i] {
			// valid share
			validShares = append(validShares, shamir.Share{
				Index:       i + 1,
				IndexScalar: *curve25519.GetScalar(uint64(i + 1)),
				S:           *epsShares[i],
			})
		}
	}

	if len(validShares) < d+1 {
		return [32]byte{}, fmt.Errorf("reconstruction of eps key failed: found %d valid shares (need d+1=%d)",
			len(validShares),
			d+1,
		)
	}

	eps, err := shamir.Reconstruct(validShares)
	if err != nil {
		return [32]byte{}, fmt.Errorf("reconstruction of eps key failed when shamir reconstructing: %w", err)
	}

	epsKey, err = SymmetricKeyFromEps((*curve25519.Scalar)(eps))
	if err != nil {
		return [32]byte{}, fmt.Errorf(
			"reconstruction of eps key failed when deriving symmetric key from eps: %w", err)
	}

	return epsKey, nil
}
