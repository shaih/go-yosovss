package resharing

import (
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// HoldShareMessage is used in the committee protocol and is the message sent by members of the holding committee
// to pass shares along to the verification committee.
type HoldShareMessage struct {
	_struct struct{}                `codec:",omitempty,omitemptyarray"`
	BiEnc      []curve25519.Ciphertext      `codec:"b_i"`
	Vi      [][]pedersen.Commitment `codec:"v_i"`
	DiEnc      []curve25519.Ciphertext      `codec:"d_i"`
	Wi      [][]pedersen.Commitment `codec:"W_i"`
	Ei      []pedersen.Commitment `codec:"e_i"`
}

// HolderComplaintMessage is used in the committee protocol is the message sent by a member k of the verification
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
// committee to pass shares along to the holding committee for the next round
type VerShareMessage struct {
	_struct struct{}            `codec:",omitempty,omitemptyarray"`
	Bk      [][]*pedersen.Share `codec:"b_k"`
	Dk      [][]*pedersen.Share `codec:"d_k"`
}
