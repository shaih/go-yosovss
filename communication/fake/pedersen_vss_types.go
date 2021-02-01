package fake

import (
	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/pedersen"
)

// SharerMessage is used in Pedersen VSS protocol and is the first message broadcasted by the sharer.
type SharerMessage struct {
	Params          pedersen.Params
	Verifications   []pedersen.Commitment
	EncryptedShares []curve25519.Ciphertext
}

// ComplaintResponseMessage is used in Pedersen VSS protocol and is the message sent by the sharer
// exposing the shares of those who broadcasted a complaint in their original share.
type ComplaintResponseMessage struct {
	ComplaintShares []pedersen.Share
}

// HoldShareMessage is used in the committee protocol and is the message sent by members of the holding committee
// to pass shares along to the verification committee.
type HoldShareMessage struct {
	holderIndex int
	Bi          [][]pedersen.Share
	Vi          [][]pedersen.Commitment
	Di          [][]pedersen.Share
	Wi          [][]pedersen.Commitment
}

// HolderComplaintMessage is used in the committee protocol is the messsage sent by a memeber k of the verification
// committee to declare the holders for which their sent shares did not verify. BComplaints and DComplaints
// are each a map that with key being the identity of the holder i and the value being a list of j values for which
// Beta_{ijk} and Delta_{ijk} are faulty, respectively.
type HolderComplaintMessage struct {
	BComplaints map[int][]int
	DComplaints map[int][]int
}

// HolderComplaintResponseMessage is used in the committee protocol and is the message that is broacasted
// by a member of the holding committee when someone in the verification committee files a complaint
// against that member
type HolderComplaintResponseMessage struct {
	BiResponse [][]*pedersen.Share
	DiResponse [][]*pedersen.Share
}

// VerShareMessage is used in the committee protocol is the message sent by members of the verification
// committee to pass shares along to the holding committee for the next
// round
type VerShareMessage struct {
	Bk [][]*pedersen.Share
	Dk [][]*pedersen.Share
}
