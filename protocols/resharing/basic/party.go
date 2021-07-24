package basic

import (
	"fmt"
	"log"

	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/protocols/resharing/common"
)

// StartCommitteeParty initiates the protocol for party i participating in a t-of-n Pedersen VSS protocol
func StartCommitteeParty(
	bc communication.BroadcastChannel,
	pks []curve25519.PublicKey,
	pk curve25519.PublicKey,
	sk curve25519.PrivateKey,
	holdCommittee []int,
	verCommittee []int,
	params *pedersen.Params,
	share *pedersen.Share,
	verifications []pedersen.Commitment,
	index int,
	t int,
	n int,
	totalRounds int,
) error {

	holdIndex := common.IntIndexOf(holdCommittee, index)
	verIndex := common.IntIndexOf(verCommittee, index)

	// Repeat for fixed number of resharing rounds
	for rounds := 0; rounds < totalRounds; rounds++ {
		var v [][][]pedersen.Commitment // Verifications for the
		var w [][][]pedersen.Commitment
		var e [][]pedersen.Commitment

		if holdIndex >= 0 { // Party is member of holding committee
			vHold, wHold, eHold, err := HoldingCommitteeShareProtocol(bc, params, *share, pks,
				holdCommittee, verCommittee,
				holdIndex, t, n)
			v = vHold
			w = wHold
			e = eHold
			if err != nil {
				return fmt.Errorf("error in holding committee share protocol: %v", err)
			}
		} else if verIndex >= 0 { // Party is member of the verification committee
			vHold, wHold, eHold, err := VerificationCommitteeProtocol(bc, pk, sk, params, holdCommittee, verIndex, t, n)
			v = vHold
			w = wHold
			e = eHold
			if err != nil {
				return fmt.Errorf("error in verification committee protocol: %v", err)
			}
		} else { // Not in a committee for the round
			bc.Send([]byte{})
			// Receive verifications broadcasted to everyone
			vHold, wHold, eHold, err := ReceiveVerifications(bc, holdCommittee, n)
			if err != nil {
				return fmt.Errorf("error in receiving holding committee verifications protocol: %v", err)
			}
			v = vHold
			w = wHold
			e = eHold
			bc.Send([]byte{})
			bc.ReceiveRound()
			bc.Send([]byte{})
			bc.ReceiveRound()
			bc.Send([]byte{})
		}

		// Get the committee for the next round
		nextHoldCommittee := NextCommitteeDeterministic(holdCommittee, len(pks))
		nextVerCommittee := NextCommitteeDeterministic(verCommittee, len(pks))

		nextHoldIndex := common.IntIndexOf(nextHoldCommittee, index)

		share = nil
		verifications = nil
		if nextHoldIndex >= 0 { // Party is a member of the next holding committee
			s, v, err := HoldingCommitteeReceiveProtocol(bc, params, v, w, e, nextHoldCommittee, verCommittee,
				nextHoldIndex, t, n)
			share = s
			verifications = v
			if err != nil {
				return fmt.Errorf("error in holding committee receive protocol: %v", err)
			}
		} else {
			bc.ReceiveRound()
		}

		holdCommittee = nextHoldCommittee
		verCommittee = nextVerCommittee
		holdIndex = common.IntIndexOf(holdCommittee, index)
		verIndex = common.IntIndexOf(verCommittee, index)
	}

	// Final round to reconstruct message
	bc.Send(msgpack.Encode(share))
	_, roundMsgs := bc.ReceiveRound()

	// Collect shares from the holding committee in the last round of the protocol
	var shares []pedersen.Share
	for i, holder := range holdCommittee {
		var share pedersen.Share
		err := msgpack.Decode(roundMsgs[holder].Payload, &share)
		if err != nil {
			return fmt.Errorf("decoding share from holder %d failed for holder %d: %v", i, holdIndex, err)
		}

		shares = append(shares, share)
	}

	// Reconstruct original message
	m, err := pedersen.VSSReconstruct(params, shares, verifications)
	if err != nil {
		return fmt.Errorf("failed to reconstruct original message for party %d: %v", index, err)
	}

	log.Printf("Party %d reconstructed message: %v", index, m)
	return nil
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

// HoldingCommitteeShareProtocol performs the actions of a party participating in the
// current holding committee for a round of the protocol, passing shares to the verification
// committee. It returns the verifications of the holders.
func HoldingCommitteeShareProtocol(
	bc communication.BroadcastChannel,
	params *pedersen.Params,
	share pedersen.Share,
	pks []curve25519.PublicKey,
	holdCommittee []int,
	verCommittee []int,
	holdIndex int,
	t int,
	n int,
) ([][][]pedersen.Commitment, [][][]pedersen.Commitment, [][]pedersen.Commitment, error) {
	// Perform a two level share of s_i and r_i to get B_i matrix of shares and V_i matrix
	// of verifications for the secrets of the second level share and D_i and W_i for the decommitments of the second
	// level sharing. E_i is the verifications of the first level share,
	// where those shares are hidden (alpha_i vector as the hidden first level share vector)
	bi, vi, di, wi, ei, err := TwoLevelShare(params, share.S, share.R, t, n)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error in creating shares of s_%d, r_%d: %v", holdIndex, holdIndex, err)
	}

	// Encrypt B_i for verification committee
	biEnc, err := EncryptSharesForVer(pks, bi, verCommittee)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error in encrypting s_i shares: %v", holdIndex)
	}

	// Encrypt D_i for verification committee
	diEnc, err := EncryptSharesForVer(pks, di, verCommittee)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error in encrypting r_i shares: %v", holdIndex)
	}

	holdShareMsg := common.HoldShareMessage{
		BiEnc: biEnc,
		Vi:    vi,
		DiEnc: diEnc,
		Wi:    wi,
		Ei:    ei,
	}

	// Send shares to verification committee, along with broadcasting the verifications
	bc.Send(msgpack.Encode(holdShareMsg))
	v, w, e, err := ReceiveVerifications(bc, holdCommittee, n)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to receive verifications: %v", err)
	}

	bc.Send([]byte{})
	// Receive potential complaints from verification committee
	_, roundMsgs := bc.ReceiveRound()

	// Initialize n x n matrix of nil shares, to be populated to respond to complaints
	biResponse := make([][]*pedersen.Share, n)
	diResponse := make([][]*pedersen.Share, n)
	for j := 0; j < n; j++ {
		for k := 0; k < n; k++ {
			biResponse[j] = make([]*pedersen.Share, n)
			diResponse[j] = make([]*pedersen.Share, n)
		}
	}

	// Iterate over all complaint messages from the verification committee and populate response matrix for the
	// shares that had complaints
	for k, verifier := range verCommittee {
		var holderComplaintMsg common.HolderComplaintMessage
		err := msgpack.Decode(roundMsgs[verifier].Payload, &holderComplaintMsg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"failed to decode complaint of verifier %d for holder %d: %v",
				verifier, holdIndex, err,
			)
		}

		for _, j := range holderComplaintMsg.BComplaints[holdIndex] {
			biResponse[j][k] = &bi[j][k]
		}

		for _, j := range holderComplaintMsg.DComplaints[holdIndex] {
			diResponse[j][k] = &di[j][k]
		}
	}

	holderComplaintResponseMsg := common.HolderComplaintResponseMessage{
		BiResponse: biResponse,
		DiResponse: diResponse,
	}

	// Send out response to complaints
	bc.Send(msgpack.Encode(holderComplaintResponseMsg))
	bc.ReceiveRound()

	// Do nothing when verification committee is sending to next holding committee
	bc.Send([]byte{})
	return v, w, e, nil
}

// VerificationCommitteeProtocol performs the actions of a party participating in the verification committee for a round
// of the protocol. It returns the verifications of the holders.
func VerificationCommitteeProtocol(
	bc communication.BroadcastChannel,
	pk curve25519.PublicKey,
	sk curve25519.PrivateKey,
	params *pedersen.Params,
	holdCommittee []int,
	verIndex int,
	t int,
	n int,
) ([][][]pedersen.Commitment, [][][]pedersen.Commitment, [][]pedersen.Commitment, error) {
	// Does not send for round where holding committee
	// sends shares to verification committee
	bc.Send([]byte{})

	// Receive shares from holding committee
	_, roundMsgs := bc.ReceiveRound()

	bComplaints := make(map[int][]int)
	dComplaints := make(map[int][]int)

	bk := make([][]*pedersen.Share, n)
	dk := make([][]*pedersen.Share, n)

	for i := 0; i < n; i++ {
		bk[i] = make([]*pedersen.Share, n)
		dk[i] = make([]*pedersen.Share, n)
	}

	v := make([][][]pedersen.Commitment, n)
	w := make([][][]pedersen.Commitment, n)
	e := make([][]pedersen.Commitment, n)

	// Checks validity of shares and construct beta_k matrix
	for i, holder := range holdCommittee {
		var holdShareMsg common.HoldShareMessage
		err := msgpack.Decode(roundMsgs[holder].Payload, &holdShareMsg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"decoding share from holder %d failed for verifier %d: %v", i, verIndex, err)
		}
		var holderBComplaints []int
		var holderDComplaints []int

		v[i] = make([][]pedersen.Commitment, n)
		w[i] = make([][]pedersen.Commitment, n)
		e[i] = make([]pedersen.Commitment, n)

		bikFailed := false
		dikFailed := false

		// Decrypt B_k shares from the holding committee
		bikBytes, err := curve25519.Decrypt(pk, sk, holdShareMsg.BiEnc[verIndex])
		var bik []pedersen.Share
		if err != nil {
			bikFailed = true
		} else {
			// Decode decrypted shares
			err = msgpack.Decode(bikBytes, &bik)
			if err != nil {
				bikFailed = true
			}
		}

		// Decrypt D_k shares from the holding committee
		dikBytes, err := curve25519.Decrypt(pk, sk, holdShareMsg.DiEnc[verIndex])
		var dik []pedersen.Share
		if err != nil {
			dikFailed = true
		} else {
			// Decode decrypted shares
			err = msgpack.Decode(dikBytes, &dik)
			if err != nil {
				dikFailed = true
			}
		}

		// Get verifications from the holding committee
		for j := 0; j < n; j++ {
			v[i][j] = holdShareMsg.Vi[j]
			w[i][j] = holdShareMsg.Wi[j]
			e[i] = holdShareMsg.Ei
		}

		if !bikFailed {
			// Check that each share is valid using verifications and construct matrix of complaints to broadcast for
			// resolution by the holder
			for j := 0; j < n; j++ {
				bIsValid, _ := pedersen.VSSVerify(params, bik[j], holdShareMsg.Vi[j])
				if bIsValid {
					bk[i][j] = &bik[j]
				} else {
					bk[i][j] = nil
					holderBComplaints = append(holderBComplaints, j)
				}
			}
		} else {
			for j := 0; j < n; j++ {
				bk[i][j] = nil
				holderBComplaints = append(holderBComplaints, j)
			}
		}

		if !dikFailed {
			// checking for share of decommitments
			for j := 0; j < n; j++ {
				dIsValid, _ := pedersen.VSSVerify(params, dik[j], holdShareMsg.Wi[j])
				if dIsValid {
					dk[i][j] = &dik[j]
				} else {
					dk[i][j] = nil
					holderDComplaints = append(holderDComplaints, j)
				}
			}
		} else {
			for j := 0; j < n; j++ {
				dk[i][j] = nil
				holderDComplaints = append(holderDComplaints, j)
			}
		}

		bComplaints[i] = holderBComplaints
		dComplaints[i] = holderDComplaints
	}

	holderComplaintMsg := common.HolderComplaintMessage{
		BComplaints: bComplaints,
		DComplaints: dComplaints,
	}

	// Sends complaints
	bc.Send(msgpack.Encode(holderComplaintMsg))
	bc.ReceiveRound()

	bc.Send([]byte{})
	// Receive complaint responses
	bc.ReceiveRound()

	verShareMsg := common.VerShareMessage{
		Bk: bk,
		Dk: dk,
	}

	// Sends shares to next holding committee
	bc.Send(msgpack.Encode(verShareMsg))

	return v, w, e, nil
}

// ReceiveVerifications receives the round of the protocol after the holding committee has constructed shares and
// extracts the verification commitments from the messages
func ReceiveVerifications(
	bc communication.BroadcastChannel,
	holdCommittee []int,
	n int,
) ([][][]pedersen.Commitment, [][][]pedersen.Commitment, [][]pedersen.Commitment, error) {
	// Receive shares from holding committee
	_, roundMsgs := bc.ReceiveRound()
	v := make([][][]pedersen.Commitment, n)
	w := make([][][]pedersen.Commitment, n)
	e := make([][]pedersen.Commitment, n)

	// Checks validity of shares and construct beta_k matrix
	for i, holder := range holdCommittee {
		var holdShareMsg common.HoldShareMessage
		err := msgpack.Decode(roundMsgs[holder].Payload, &holdShareMsg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decoding share from holder %d failed: %v", i, err)
		}

		v[i] = make([][]pedersen.Commitment, n)
		w[i] = make([][]pedersen.Commitment, n)
		e[i] = make([]pedersen.Commitment, n)
		for j := 0; j < n; j++ {
			v[i][j] = holdShareMsg.Vi[j]
			w[i][j] = holdShareMsg.Wi[j]
			e[i] = holdShareMsg.Ei
		}
	}

	return v, w, e, nil
}

// HoldingCommitteeReceiveProtocol performs the actions of a party participating in the next holding committee for a
// round of the protocol, receiving shares from the verification committee
func HoldingCommitteeReceiveProtocol(
	bc communication.BroadcastChannel,
	params *pedersen.Params,
	v [][][]pedersen.Commitment,
	w [][][]pedersen.Commitment,
	e [][]pedersen.Commitment,
	holdCommittee []int,
	verCommittee []int,
	holdIndex int,
	t int,
	n int,
) (*pedersen.Share, []pedersen.Commitment, error) {

	_, roundMsgs := bc.ReceiveRound()

	bj := make([][]pedersen.Share, n)
	dj := make([][]pedersen.Share, n)
	for i := 0; i < n; i++ {
		bj[i] = make([]pedersen.Share, n)
		dj[i] = make([]pedersen.Share, n)
	}

	// Construct B_j matrix, the matrix of second level shares, from the verification committee or from
	// resolved complaints
	for k, verifier := range verCommittee {
		var verShareMsg common.VerShareMessage
		err := msgpack.Decode(roundMsgs[verifier].Payload, &verShareMsg)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"decoding share from verifier %d failed for holder %d: %v",
				k, holdIndex, err,
			)
		}

		// Obtain shares from the verification committee,
		// giving the possibility of leaving some out due to faulty shares
		for i := 0; i < n; i++ {
			if verShareMsg.Bk[i][holdIndex] != nil {
				bj[i][k] = *verShareMsg.Bk[i][holdIndex]
			}
			if verShareMsg.Dk[i][holdIndex] != nil {
				dj[i][k] = *verShareMsg.Dk[i][holdIndex]
			}
		}
	}

	var aj []curve25519.Scalar
	var cj []curve25519.Scalar
	var indicesScalar []curve25519.Scalar
	var indices []int

	i := 0
	// Use the second level shares to reconstruct the first level shares
	for i < n && len(aj) < t {
		var bij []pedersen.Share
		var dij []pedersen.Share
		for k := 0; k < n; k++ {
			bij = append(bij, bj[i][k])
			dij = append(dij, dj[i][k])
		}
		aij, err1 := pedersen.VSSReconstruct(params, bij, v[i][holdIndex])
		cij, err2 := pedersen.VSSReconstruct(params, dij, w[i][holdIndex])
		if err1 == nil && err2 == nil { // Use corresponding shares of alpha and gamma
			aj = append(aj, curve25519.Scalar(*aij))
			cj = append(cj, curve25519.Scalar(*cij))
			// Track the index of the successful share
			indicesScalar = append(indicesScalar, curve25519.GetScalar(uint64(i+1)))
			indices = append(indices, i+1)
		}
		i++
	}

	// Return an error if we are unable to reconstruct at least t of the first level shares
	if len(aj) < t {
		return nil, nil, fmt.Errorf(
			"unable to reconstruct sufficient alpha_i and gamma_i for holder %d",
			holdIndex,
		)
	}

	// Of the reconstructed shares, we take the first t of them and compute the Lagrange coefficients corresponding to
	// those shares
	lambdas, err := curve25519.LagrangeCoeffs(indicesScalar, curve25519.GetScalar(0))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute Lagrange coefficients for holder %d: %v", holdIndex, err)
	}

	share := pedersen.Share{
		Index:       holdIndex + 1,
		IndexScalar: curve25519.GetScalar(uint64(holdIndex + 1)),
		S:           curve25519.ScalarZero,
		R:           curve25519.ScalarZero,
	}

	verifications := make([]pedersen.Commitment, t)

	for i := 0; i < t; i++ {
		// Computing the linear combination of the previous shares with Lagrange coefficients to construct share
		// for the next round of the protocol.
		share.S = curve25519.AddScalar(share.S, curve25519.MultScalar(lambdas[i], aj[i]))
		share.R = curve25519.AddScalar(share.R, curve25519.MultScalar(lambdas[i], cj[i]))
		testShare := pedersen.Share{
			Index:       holdIndex + 1,
			IndexScalar: curve25519.GetScalar(uint64(holdIndex + 1)),
			S:           aj[i],
			R:           cj[i],
		}

		// Verification of the first level share using the E matrix to confirm validity of the first level
		isVerified, err := pedersen.VSSVerify(params, testShare, e[indices[i]-1])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to verify share %d: %v", holdIndex, err)
		} else if !isVerified {
			return nil, nil, fmt.Errorf("share could not be verified %d: %v", holdIndex, err)
		}
		// Computing the new verifications of the first level through doing the linear combination in the exponent
		for j := 0; j < t; j++ {
			prod, err := curve25519.MultPointScalar(curve25519.Point(e[indices[i]-1][j]), lambdas[i])
			if err != nil {
				return nil, nil, fmt.Errorf("unable to compute new verifications %d: %v", holdIndex, err)
			}
			var sum curve25519.Point
			if i == 0 {
				sum = prod
			} else {
				sum, err = curve25519.AddPoint(curve25519.Point(verifications[j]), prod)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to compute new verifications %d: %v", holdIndex, err)
				}
			}
			verifications[j] = pedersen.Commitment(sum)
		}
	}

	return &share, verifications, nil
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
