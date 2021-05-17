package resharing

import (
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/shamir"
)

// HoldShareMessage is used in the committee protocol and is the message sent by members of the holding committee
// to pass shares along to the verification committee.
// BiEnc are the shares s_ijk meant where BiEnc[k] is the set of shares for the kth member of the verification committee
// Vi contains the verifications for the shares
// DiEnc are the shares r_ijk meant where DiEnc[k] is the set of shares for the kth member of the verification committee
// Wi contains the verifications for the shares of the r_ijk, where Wi[j][k] is the verification of the r_ijk share
// Ei contains the verification of the share of the s_ijm where Ei[j] is the verification for the share s_ij
type HoldShareMessage struct {
	_struct struct{}                `codec:",omitempty,omitemptyarray"`
<<<<<<< HEAD
	BiEnc   []curve25519.Ciphertext `codec:"bi"`
	Vi      [][]pedersen.Commitment `codec:"vi"`
	DiEnc   []curve25519.Ciphertext `codec:"di"`
	Wi      [][]pedersen.Commitment `codec:"Wi"`
	Ei      []pedersen.Commitment 	`codec:"ei"`
}

// FutureBroadcastShare is the share in the future broadcast protocol to reconstruct the symmetric key, along with a
// corresponding signature to prove the validity of each future broadcast share
type FutureBroadcastShare struct {
	FBShares    []shamir.Share
	FBShareSigs []curve25519.Signature
}

// HoldShareFBMessage is used in the committee protocol and is the message sent by members of the holding committee
// to pass shares along to the verification committee, using the future broadcast protocol.
// BiEnc are the shares s_ijk meant where BiEnc[k] is the set of shares for the kth member of the verification committee
// Vi contains the verifications for the shares
// DiEnc are the shares r_ijk meant where DiEnc[k] is the set of shares for the kth member of the verification committee
// Wi contains the verifications for the shares of the r_ijk, where Wi[j][k] is the verification of the r_ijk share
// Ei contains the verification of the share of the s_ijm where Ei[j] is the verification for the share s_ij
type HoldShareFBMessage struct {
	_struct     struct{}                         `codec:",omitempty,omitemptyarray"`
	BiEnc       []curve25519.Ciphertext          `codec:"bi"`
	Vi          [][]pedersen.Commitment          `codec:"vi"`
	DiEnc       []curve25519.Ciphertext          `codec:"di"`
	Wi          [][]pedersen.Commitment          `codec:"Wi"`
	Ei          []pedersen.Commitment            `codec:"ei"`
	SymmEncBi   []curve25519.SymmetricCiphertext `codec:"se_bi"`
	SymmEncDi   []curve25519.SymmetricCiphertext `codec:"se_di"`
	FBShareiEnc []curve25519.Ciphertext          `codec:"fb"`
=======
	BiEnc   []curve25519.Ciphertext `codec:"b_i"`
	Vi      [][]pedersen.Commitment `codec:"v_i"`
	DiEnc   []curve25519.Ciphertext `codec:"d_i"`
	Wi      [][]pedersen.Commitment `codec:"W_i"`
	Ei      []pedersen.Commitment   `codec:"e_i"`
>>>>>>> a490ed4a3f6bf14dc278ddcb07d82829f54f07d0
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

// FutureBroadcastResponseMessage is used in the committee protocol and is the message that is broadcasted by a
// member of the future broadcast committee to respond to complaints from the verification committee
type FutureBroadcastResponseMessage struct {
	_struct  struct{}                  `codec:",omitempty,omitemptyarray"`
	FBShares [][]*shamir.Share         `codec:"share_l"`
	FBSigs   [][]*curve25519.Signature `codec:"sig_l"`
}

// VerShareMessage is used in the committee protocol is the message sent by members of the verification
// committee to pass shares along to the holding committee for the next round
type VerShareMessage struct {
	_struct struct{}            `codec:",omitempty,omitemptyarray"`
	Bk      [][]*pedersen.Share `codec:"b_k"`
	Dk      [][]*pedersen.Share `codec:"d_k"`
}

// VerShareMessageFB is used in the committee protocol is the message sent by members of the verification
// committee to pass shares along to the holding committee for the next round and also complaints to be resolved by
// the verification committee
type VerShareMessageFB struct {
	_struct 	struct{}            	`codec:",omitempty,omitemptyarray"`
	BkEnc      []curve25519.Ciphertext  `codec:"b_k"`
	DkEnc      []curve25519.Ciphertext  `codec:"d_k"`
	BComplaints map[int][]int 			`codec:"b_compl"`
	DComplaints map[int][]int 			`codec:"d_compl"`
}
