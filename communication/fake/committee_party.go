package fake

import (
	"fmt"

	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/encoding"
	"github.com/shaih/go-yosovss/pedersen"
)

// CommitteeParty is a party that performs the Pedersen VSS protocol
// and holds a share of a shared secret
type CommitteeParty struct {
	ID      int
	Channel PartyBroadcastChannel
}

// NewCommitteeParty returns a new CommitteeParty
func NewCommitteeParty(i int) CommitteeParty {
	return CommitteeParty{
		ID:      i,
		Channel: NewPartyBroadcastChannel(i),
	}
}

// GetID returns the ID of the party
func (p CommitteeParty) GetID() int {
	return p.ID
}

// GetBroadcastChannel returns the channel associated with the party
func (p CommitteeParty) GetBroadcastChannel() communication.BroadcastChannel {
	return p.Channel
}

// StartProtocol initiates the protocol for party i participating in a t-of-n Pedersen VSS protocol
func (p CommitteeParty) StartProtocol(
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	holdCommittee []int,
	verCommittee []int,
	params pedersen.Params,
	share *pedersen.Share,
	index int,
	t int,
	n int,
) error {
	// Repeat for fixed number of rounds
	for rounds := 0; rounds < 5; rounds++ {

		holdIndex := intIndexOf(holdCommittee, index)
		verIndex := intIndexOf(holdCommittee, index)

		if holdIndex >= 0 {
			p.HoldingCommitteeShareProtocol(params, *share, holdCommittee, verCommittee, holdIndex, t, n)
		} else if verIndex >= 0 {
			p.VerificationCommitteeProtocol(params, holdCommittee, verIndex, t, n)
		} else {
			// Do nothing if not in a committee
			for i := 0; i < 4; i++ {
				p.Channel.Send([]byte{})
				p.Channel.ReceiveRound()
			}
		}

		nextHoldCommittee := NextCommittee(holdCommittee, len(publicKeys))
		nextVerCommittee := NextCommittee(verCommittee, len(publicKeys))

		nextHoldIndex := intIndexOf(nextHoldCommittee, index)
		if nextHoldIndex >= 0 {

		} else {

		}

		holdCommittee = nextHoldCommittee
		verCommittee = nextVerCommittee
	}

	return nil
}

// TwoLevelShare performs a Shamir share followed by Pedersen VSS, and returns the resulting
// matrix of shares and verifications
func TwoLevelShare(
	params pedersen.Params,
	m pedersen.Message,
	t int,
	n int,
) ([][]pedersen.Share, [][]pedersen.Commitment, error) {
	shareList, _, err := pedersen.VSSShare(&params, pedersen.Message(m), t, n)
	if err != nil {
		return nil, nil, fmt.Errorf("error in first level share: %v", err)
	}

	var shareMatrix [][]pedersen.Share
	var verMatrix [][]pedersen.Commitment

	for i, share := range *shareList {
		si, vi, err := pedersen.VSSShare(&params, pedersen.Message(share.S), t, n)
		if err != nil {
			return nil, nil, fmt.Errorf("error in second level share: %v", err)
		}
		shareMatrix[i] = *si
		verMatrix[i] = *vi

	}

	return shareMatrix, verMatrix, nil
}

// HoldingCommitteeShareProtocol performs the actions of a party participating in the
// current holding committee for a round of the protocol, passing shares to the verification
// committee
func (p CommitteeParty) HoldingCommitteeShareProtocol(
	params pedersen.Params,
	share pedersen.Share,
	holdCommittee []int,
	verCommittee []int,
	holdIndex int,
	t int,
	n int,
) error {

	// Perform a two level share of s_i to get Beta_i matrix of shares and V_i matrix
	// of verifications (with alpha_i vector as the hidden first level share vector)
	bi, vi, err := TwoLevelShare(params, pedersen.Message(share.S), t, n)
	if err != nil {
		return fmt.Errorf("error in creating shares of s_%d: %v", holdIndex, err)
	}

	// Perform a two level share of r_i to get Delta_i matrix of shares and W_i matrix
	// of verifications (with gamma_i vector as the hidden first level share vector)
	di, wi, err := TwoLevelShare(params, pedersen.Message(share.R), t, n)
	if err != nil {
		return fmt.Errorf("error in creating shares of r_%d: %v", holdIndex, err)
	}

	holdShareMessage := HoldShareMessage{
		Bi: bi,
		Vi: vi,
		Di: di,
		Wi: wi,
	}

	// Send shares to verification committee
	p.Channel.Send(encoding.EncodeReflect(holdShareMessage))
	p.Channel.ReceiveRound()

	p.Channel.Send([]byte{})
	// Receive potential complaints from verification committee
	_, roundMsgs := p.Channel.ReceiveRound()

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
		err := encoding.DecodeReflect(roundMsgs[verifier].Payload, &holderComplaintMsg)
		if err != nil {
			return fmt.Errorf("failed to decode complaint of verifier %d for holder %d: %v", verifier, holdIndex, err)
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
	p.Channel.Send(encoding.EncodeReflect(holderComplaintResponseMsg))
	p.Channel.ReceiveRound()

	// Do nothing when verification committee is sending to next holding committee
	p.Channel.Send([]byte{})

	return nil
}

// VerificationCommitteeProtocol performs the actions of a party participating in the
// verification committee for a round of the protocol
func (p CommitteeParty) VerificationCommitteeProtocol(
	params pedersen.Params,
	holdCommittee []int,
	verIndex int,
	t int,
	n int,
) error {

	// Does not send for round where holding committee
	// sends shares to verification committee
	p.Channel.Send([]byte{})

	// Receive shares from holding committee
	_, roundMsgs := p.Channel.ReceiveRound()

	var bComplaints map[int][]int
	var bk [][]*pedersen.Share
	var dComplaints map[int][]int
	var dk [][]*pedersen.Share

	// Checks validity of shares and construct beta_k matrix
	for i, holder := range holdCommittee {
		var holdShareMsg HoldShareMessage
		err := encoding.DecodeReflect(roundMsgs[holder].Payload, &holdShareMsg)
		if err != nil {
			return fmt.Errorf("Decoding share from holder %d failed for verifier %d: %v", i, verIndex, err)
		}
		var holderBComplaints []int
		var holderDComplaints []int

		for j := 0; j < n; j++ {
			bIsValid, err := pedersen.VSSVerify(&params, holdShareMsg.Bi[j][verIndex], holdShareMsg.Vi[j])
			if err != nil {
				return fmt.Errorf("Validating share from holder %d failed for verifier %d: %v", i, verIndex, err)
			}
			dIsValid, err := pedersen.VSSVerify(&params, holdShareMsg.Di[j][verIndex], holdShareMsg.Wi[j])
			if err != nil {
				return fmt.Errorf("Validating verification from holder %d failed for verifier %d: %v", i, verIndex, err)
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
	p.Channel.Send(encoding.EncodeReflect(holderComplaintMsg))
	p.Channel.ReceiveRound()

	p.Channel.Send([]byte{})
	// Receive complaint responses
	_, roundMsgs = p.Channel.ReceiveRound()

	verShareMsg := VerShareMessage{
		Bk: bk,
		Dk: dk,
	}

	// Sends shares to next holding committee
	p.Channel.Send(encoding.EncodeReflect(verShareMsg))

	return nil
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

// intSliceContains checks if a slice contains a number
func intSliceContains(list []int, val int) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}

	return false
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
