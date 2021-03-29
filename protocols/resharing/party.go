package resharing

import (
	"fmt"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"log"
)

// StartCommitteeParty initiates the protocol for party i participating in a t-of-n Pedersen VSS protocol
func StartCommitteeParty(
	bc communication.BroadcastChannel,
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	holdCommittee []int,
	verCommittee []int,
	params *pedersen.Params,
	share *pedersen.Share,
	verifications []pedersen.Commitment,
	index int,
	t int,
	n int,
) error {

	holdIndex := intIndexOf(holdCommittee, index)
	verIndex := intIndexOf(verCommittee, index)

	// Repeat for fixed number of rounds
	for rounds := 0; rounds < 1; rounds++ {
		var v [][][]pedersen.Commitment
		var w [][][]pedersen.Commitment
		var e [][]pedersen.Commitment
		var f [][]pedersen.Commitment

		if holdIndex >= 0 {
			vHold, eHold, wHold, fHold, err := HoldingCommitteeShareProtocol(bc, params, *share, holdCommittee, verCommittee,
				holdIndex, t, n)
			v = vHold
			e = eHold
			w = wHold
			f = fHold
			if err != nil {
				return fmt.Errorf("error in holding committee share protocol: %v", err)
			}
		} else if verIndex >= 0 {
			vHold, eHold, wHold, fHold, err := VerificationCommitteeProtocol(bc, params, holdCommittee, verIndex, t, n)
			v = vHold
			e = eHold
			w = wHold
			f = fHold
			if err != nil {
				return fmt.Errorf("Error in verification committee protocol: %v", err)
			}
		} else {
			// Do nothing if not in a committee
			bc.Send([]byte{})
			vHold, eHold, wHold, fHold, err := ReceiveVerifications(bc, holdCommittee, n)
			if err != nil {
				return fmt.Errorf("error in receiving holding committee verifications protocol: %v", err)
			}
			v = vHold
			e = eHold
			w = wHold
			f = fHold
			bc.Send([]byte{})
			bc.ReceiveRound()
			bc.Send([]byte{})
			bc.ReceiveRound()
			bc.Send([]byte{})
		}

		nextHoldCommittee := NextCommittee(holdCommittee, len(publicKeys))
		nextVerCommittee := NextCommittee(verCommittee, len(publicKeys))

		nextHoldIndex := intIndexOf(nextHoldCommittee, index)

		share = nil
		verifications = nil
		if nextHoldIndex >= 0 {
			s, v, err := HoldingCommitteeReceiveProtocol(bc, params, v, e, w, f, nextHoldCommittee, verCommittee,
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
		holdIndex = intIndexOf(holdCommittee, index)
		verIndex = intIndexOf(verCommittee, index)
	}

	// Final round to reconstruct message
	bc.Send(msgpack.Encode(share))

	_, roundMsgs := bc.ReceiveRound()

	var shares []pedersen.Share
	for i, holder := range holdCommittee {
		var share pedersen.Share
		err := msgpack.Decode(roundMsgs[holder].Payload, &share)
		if err != nil {
			return fmt.Errorf("decoding share from holder %d failed for holder %d: %v", i, holdIndex, err)
		}

		shares = append(shares, share)
	}

	var sum curve25519.Scalar
	validShareValues := make([]curve25519.Scalar, t)
	for i := 0; i < t; i++ {
		validShareValues[i] = shares[i].IndexScalar
	}
	lambdas, err := curve25519.LagrangeCoeffs(validShareValues, curve25519.GetScalar(uint64(0)))
	if err != nil {
		return fmt.Errorf("error in polynomial interpolation")
	}

	for i := 0; i < t; i++ {
		sum = curve25519.AddScalar(sum, curve25519.MultScalar(shares[i].S, lambdas[i]))
	}

	m := pedersen.Message(sum)

	log.Printf("Party %d reconstructed message: %v", index, m)


	return nil
}

// TwoLevelShare performs a Shamir share followed by Pedersen VSS, and returns the resulting
// matrix of shares and verifications
func TwoLevelShare(
	params *pedersen.Params,
	m pedersen.Message,
	t int,
	n int,
) ([][]pedersen.Share, [][]pedersen.Commitment, []pedersen.Commitment, error) {
	shareList, verList, err := pedersen.VSSShare(params, pedersen.Message(m), t, n)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error in first level share: %v", err)
	}

	var shareMatrix [][]pedersen.Share
	var verMatrix [][]pedersen.Commitment

	for _, share := range shareList {
		si, vi, err := pedersen.VSSShare(params, pedersen.Message(share.S), t, n)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error in second level share: %v", err)
		}
		shareMatrix = append(shareMatrix, si)
		verMatrix = append(verMatrix, vi)
	}

	return shareMatrix, verMatrix, verList, nil
}

// HoldingCommitteeShareProtocol performs the actions of a party participating in the
// current holding committee for a round of the protocol, passing shares to the verification
// committee. It returns the verifications of the holders.
func HoldingCommitteeShareProtocol(
	bc communication.BroadcastChannel,
	params *pedersen.Params,
	share pedersen.Share,
	holdCommittee []int,
	verCommittee []int,
	holdIndex int,
	t int,
	n int,
) ([][][]pedersen.Commitment, [][]pedersen.Commitment, [][][]pedersen.Commitment, [][]pedersen.Commitment, error) {
	// Perform a two level share of s_i to get Beta_i matrix of shares and V_i matrix
	// of verifications (with alpha_i vector as the hidden first level share vector)
	bi, vi, ei, err := TwoLevelShare(params, pedersen.Message(share.S), t, n)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error in creating shares of s_%d: %v", holdIndex, err)
	}

	// Perform a two level share of r_i to get Delta_i matrix of shares and W_i matrix
	// of verifications (with gamma_i vector as the hidden first level share vector)
	di, wi, fi, err := TwoLevelShare(params, pedersen.Message(share.R), t, n)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error in creating shares of r_%d: %v", holdIndex, err)
	}

	// TODO: Encrypt columns of Bi and Di for individual verifiers

	holdShareMsg := HoldShareMessage{
		Bi: bi,
		Vi: vi,
		Ei: ei,
		Di: di,
		Wi: wi,
		Fi: fi,
	}

	// Send shares to verification committee
	bc.Send(msgpack.Encode(holdShareMsg))
	v, e, w, f, err := ReceiveVerifications(bc, holdCommittee, n)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unable to receive verifications: %v", err)
	}

	bc.Send([]byte{})
	// Receive potential complaints from verification committee
	_, roundMsgs := bc.ReceiveRound()

	// Initialize nxn matrix of nil shares, to be populated to respond to complaints
	biResponse := make([][]*pedersen.Share, n)
	diResponse := make([][]*pedersen.Share, n)
	for j := 0; j < n; j++ {
		for k := 0; k < n; k++ {
			biResponse[j] = make([]*pedersen.Share, n)
			diResponse[j] = make([]*pedersen.Share, n)
		}
	}

	// Iterate over all complaint messages from the verification committee
	for k, verifier := range verCommittee {
		var holderComplaintMsg HolderComplaintMessage
		err := msgpack.Decode(roundMsgs[verifier].Payload, &holderComplaintMsg)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to decode complaint of verifier %d for holder %d: %v", verifier, holdIndex, err)
		}

		for _, j := range holderComplaintMsg.BComplaints[holdIndex] {
			biResponse[j][k] = &bi[j][k]
		}

		for _, j := range holderComplaintMsg.DComplaints[holdIndex] {
			diResponse[j][k] = &di[j][k]
		}
	}

	holderComplaintResponseMsg := HolderComplaintResponseMessage{
		BiResponse: biResponse,
		DiResponse: diResponse,
	}

	// Send out response to complaints
	bc.Send(msgpack.Encode(holderComplaintResponseMsg))
	bc.ReceiveRound()

	// Do nothing when verification committee is sending to next holding committee
	bc.Send([]byte{})
	return v, e, w, f, nil
}

// VerificationCommitteeProtocol performs the actions of a party participating in the verification committee for a round
// of the protocol. It returns the verifications of the holders.
func VerificationCommitteeProtocol(
	bc communication.BroadcastChannel,
	params *pedersen.Params,
	holdCommittee []int,
	verIndex int,
	t int,
	n int,
) ([][][]pedersen.Commitment, [][]pedersen.Commitment, [][][]pedersen.Commitment, [][]pedersen.Commitment, error) {
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
	e := make([][]pedersen.Commitment, n)
	w := make([][][]pedersen.Commitment, n)
	f := make([][]pedersen.Commitment, n)

	// Checks validity of shares and construct beta_k matrix
	for i, holder := range holdCommittee {
		var holdShareMsg HoldShareMessage
		err := msgpack.Decode(roundMsgs[holder].Payload, &holdShareMsg)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("decoding share from holder %d failed for verifier %d: %v", i, verIndex, err)
		}
		var holderBComplaints []int
		var holderDComplaints []int

		v[i] = make([][]pedersen.Commitment, n)
		e[i] = make([]pedersen.Commitment, n)
		w[i] = make([][]pedersen.Commitment, n)
		f[i] = make([]pedersen.Commitment, n)
		for j := 0; j < n; j++ {
			v[i][j] = holdShareMsg.Vi[j]
			e[i] = holdShareMsg.Ei
			w[i][j] = holdShareMsg.Wi[j]
			f[i] = holdShareMsg.Fi

			bIsValid, err := pedersen.VSSVerify(params, holdShareMsg.Bi[j][verIndex], holdShareMsg.Vi[j])
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("validating share from holder %d failed for verifier %d: %v", i, verIndex, err)
			}
			dIsValid, err := pedersen.VSSVerify(params, holdShareMsg.Di[j][verIndex], holdShareMsg.Wi[j])
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("validating verification from holder %d failed for verifier %d: %v", i, verIndex, err)
			}

			if bIsValid {
				bk[i][j] = &holdShareMsg.Bi[j][verIndex]
			} else {
				bk[i][j] = nil
				holderBComplaints = append(holderBComplaints, j)
			}

			if dIsValid {
				dk[i][j] = &holdShareMsg.Di[j][verIndex]
			} else {
				dk[i][j] = nil
				holderDComplaints = append(holderDComplaints, j)
			}
		}

		bComplaints[i] = holderBComplaints
		dComplaints[i] = holderDComplaints

	}

	holderComplaintMsg := HolderComplaintMessage{
		BComplaints: bComplaints,
		DComplaints: dComplaints,
	}

	// Sends complaints
	bc.Send(msgpack.Encode(holderComplaintMsg))
	bc.ReceiveRound()

	bc.Send([]byte{})
	// Receive complaint responses
	bc.ReceiveRound()

	verShareMsg := VerShareMessage{
		Bk: bk,
		Dk: dk,
	}

	// Sends shares to next holding committee
	bc.Send(msgpack.Encode(verShareMsg))

	return v, e, w, f, nil
}

// ReceiveVerifications receives the round of the protocol after the holding committee has constructed shares and
// extracts the verification commitments from the messages
func ReceiveVerifications(
	bc communication.BroadcastChannel,
	holdCommittee []int,
	n int,
) ([][][]pedersen.Commitment, [][]pedersen.Commitment, [][][]pedersen.Commitment, [][]pedersen.Commitment, error) {
	// Receive shares from holding committee
	_, roundMsgs := bc.ReceiveRound()
	v := make([][][]pedersen.Commitment, n)
	e := make([][]pedersen.Commitment, n)
	w := make([][][]pedersen.Commitment, n)
	f := make([][]pedersen.Commitment, n)

	// Checks validity of shares and construct beta_k matrix
	for i, holder := range holdCommittee {
		var holdShareMsg HoldShareMessage
		err := msgpack.Decode(roundMsgs[holder].Payload, &holdShareMsg)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("decoding share from holder %d failed: %v", i, err)
		}

		v[i] = make([][]pedersen.Commitment, n)
		e[i] = make([]pedersen.Commitment, n)
		w[i] = make([][]pedersen.Commitment, n)
		f[i] = make([]pedersen.Commitment, n)
		for j := 0; j < n; j++ {
			v[i][j] = holdShareMsg.Vi[j]
			e[i] = holdShareMsg.Ei
			w[i][j] = holdShareMsg.Wi[j]
			f[i] = holdShareMsg.Fi
		}
	}

	return v, e, w, f, nil
}

// HoldingCommitteeReceiveProtocol performs the actions of a party participating in the next holding committee for a
// round of the protocol, receiving shares from the verification committee
func HoldingCommitteeReceiveProtocol(
	bc communication.BroadcastChannel,
	params *pedersen.Params,
	v [][][]pedersen.Commitment,
	e [][]pedersen.Commitment,
	w [][][]pedersen.Commitment,
	f [][]pedersen.Commitment,
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

	// Construct B_j matrix
	for k, verifier := range verCommittee {
		var verShareMsg VerShareMessage
		err := msgpack.Decode(roundMsgs[verifier].Payload, &verShareMsg)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding share from verifier %d failed for holder %d: %v", k, holdIndex, err)
		}

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
	var indices []curve25519.Scalar

	i := 0
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
			indices = append(indices, curve25519.GetScalar(uint64(i)))
		}
		i++
	}

	if len(aj) < t {
		return nil, nil, fmt.Errorf("unable to reconstruct sufficient alpha_i and gamma_i for holder %d", holdIndex)
	}

	lambdas, err := curve25519.LagrangeCoeffs(indices, curve25519.GetScalar(uint64(holdIndex)))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute Lagrange coefficients for holder %d: %v", holdIndex, err)
	}

	share := pedersen.Share{
		Index:       holdIndex,
		IndexScalar: curve25519.GetScalar(uint64(holdIndex)),
		R:           curve25519.ScalarZero,
		S:           curve25519.ScalarZero,
	}

	verifications := make([]pedersen.Commitment, t)

	for i := 0; i < t; i++ {
		share.R = curve25519.AddScalar(share.R, curve25519.MultScalar(lambdas[i], aj[i]))
		share.S = curve25519.AddScalar(share.S, curve25519.MultScalar(lambdas[i], cj[i]))
	}


	return &share, verifications, nil
}

// NextCommittee is a naive method for deterministically selecting the next
// set of members belonging to
func NextCommittee(committee []int, total int) []int {
	n := len(committee)
	var nextCommittee []int

	for _, index := range committee {
		nextCommittee = append(nextCommittee, (index+n)%total)
	}

	return nextCommittee
}

// intIndexOf returns the first position in a slice that has a value,
// or -1 if the slice does not contain the value.
func intIndexOf(list []int, val int) int {
	for i, v := range list {
		if v == val {
			return i
		}
	}
	return -1
}
