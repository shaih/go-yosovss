package fake

import (
	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/pedersen"
)

// SharerMessage is used in Pedersen VSS protocol and is the first message broadcasted by the sharer.
type SharerMessage struct {
	_struct         struct{}                `codec:",omitempty,omitemptyarray"`
	Params          pedersen.Params         `codec:"params"`
	Verifications   []pedersen.Commitment   `codec:"vers"`
	EncryptedShares []curve25519.Ciphertext `codec:"enc_shares"`
}

// ComplaintResponseMessage is used in Pedersen VSS protocol and is the message sent by the sharer
// exposing the shares of those who broadcasted a complaint in their original share.
type ComplaintResponseMessage struct {
	_struct         struct{}         `codec:",omitempty,omitemptyarray"`
	ComplaintShares []pedersen.Share `codec:"cmpl_shares"`
}

// HoldShareMessage is used in the committee protocol and is the message sent by members of the holding committee
// to pass shares along to the verification committee.
type HoldShareMessage struct {
	_struct struct{}                `codec:",omitempty,omitemptyarray"`
	Bi      [][]pedersen.Share      `codec:"b_i"`
	Vi      [][]pedersen.Commitment `codec:"v_i"`
	Di      [][]pedersen.Share      `codec:"d_i"`
	Wi      [][]pedersen.Commitment `codec:"w_i"`
}

// HolderComplaintMessage is used in the committee protocol is the messsage sent by a memeber k of the verification
// committee to declare the holders for which their sent shares did not verify. BComplaints and DComplaints
// are each a map that with key being the identity of the holder i and the value being a list of j values for which
// Beta_{ijk} and Delta_{ijk} are faulty, respectively.
type HolderComplaintMessage struct {
	_struct     struct{}      `codec:",omitempty,omitemptyarray"`
	BComplaints map[int][]int `codec:"b_compl"`
	DComplaints map[int][]int `codec:"d_compl"`
}

// HolderComplaintResponseMessage is used in the committee protocol and is the message that is broacasted
// by a member of the holding committee when someone in the verification committee files a complaint
// against that member
type HolderComplaintResponseMessage struct {
	_struct    struct{}            `codec:",omitempty,omitemptyarray"`
	BiResponse [][]*pedersen.Share `codec:"b_i_res"`
	DiResponse [][]*pedersen.Share `codec:"d_i_res"`
}

// VerShareMessage is used in the committee protocol is the message sent by members of the verification
// committee to pass shares along to the holding committee for the next
// round
type VerShareMessage struct {
	_struct struct{}            `codec:",omitempty,omitemptyarray"`
	Bk      [][]*pedersen.Share `codec:"b_k"`
	Dk      [][]*pedersen.Share `codec:"d_k"`
}
