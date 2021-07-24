package common

import (
	"fmt"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// EncryptSharesForVer encrypts the n x n matrix of shares for the verification committee
func EncryptSharesForVer(
	pks []curve25519.PublicKey,
	shares [][]pedersen.Share,
	verCommittee []int,
) ([]curve25519.Ciphertext, error) {

	encryptedShares := make([]curve25519.Ciphertext, len(shares))

	for k := 0; k < len(shares); k++ {
		sharesK := make([]pedersen.Share, len(shares)) // Shares for an individual verification committee member
		// Create a list of shares for verification committee member k
		for j := 0; j < len(shares); j++ {
			sharesK[j] = shares[j][k]
		}

		// Encrypt using the key of verifidation committee member k
		encryptedShare, err := curve25519.Encrypt(pks[verCommittee[k]], msgpack.Encode(sharesK))
		encryptedShares[k] = encryptedShare
		if err != nil {
			return nil, fmt.Errorf("unable to encrypt using the public key of party %d", verCommittee[k])
		}
	}

	return encryptedShares, nil
}

// NextCommitteeDeterministic is a naive method for deterministically selecting the next
// set of members belonging to
func NextCommitteeDeterministic(committee []int, total int) []int {
	n := len(committee)
	var nextCommittee []int

	for _, index := range committee {
		nextCommittee = append(nextCommittee, (index+n)%total)
	}

	return nextCommittee
}

// TwoLevelShare performs a sharing and then subsequently does another Pedersen VSS for the shares of the first sharing
func TwoLevelShare(
	params *pedersen.Params,
	r curve25519.Scalar,
	s curve25519.Scalar,
	t int,
	n int,
) ([][]pedersen.Share,
	[][]pedersen.Commitment,
	[][]pedersen.Share,
	[][]pedersen.Commitment,
	[]pedersen.Commitment,
	error,
) {
	// Perform the first level share with the given secret and decommitment. These shares form the alpha_ijs
	// and the verifications are the E_ijs
	shareList, verList, err := pedersen.VSSShareFixedR(params, pedersen.Message(r), pedersen.Decommitment(s), t, n)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("error in first level share: %v", err)
	}

	sShareMatrix := make([][]pedersen.Share, n)
	rShareMatrix := make([][]pedersen.Share, n)
	sVerMatrix := make([][]pedersen.Commitment, n)
	rVerMatrix := make([][]pedersen.Commitment, n)

	// For every share of the first level share, we perform another Pedersen sharing of both the r and s of the share
	for i, share := range shareList {
		si, vi, err := pedersen.VSSShare(params, pedersen.Message(share.S), t, n)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("error in second level share of s: %v", err)
		}
		ri, ui, err := pedersen.VSSShare(params, pedersen.Message(share.R), t, n)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("error in second level share of r: %v", err)
		}

		sShareMatrix[i] = si
		sVerMatrix[i] = vi
		rShareMatrix[i] = ri
		rVerMatrix[i] = ui
	}

	// We return a matrix of the shares and verifications of the two level share, as well as the verifications
	// of the first level share (verList)
	return sShareMatrix, sVerMatrix, rShareMatrix, rVerMatrix, verList, nil
}

