package fake

import (
	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/pedersen"
)

// SharerMessage is the first message broadcasted by the sharer
type SharerMessage struct {
	_struct         struct{}                `codec:",omitempty,omitemptyarray"`
	Params          pedersen.Params         `codec:"params"`
	Verifications   []pedersen.Commitment   `codec:"vers"`
	EncryptedShares []curve25519.Ciphertext `codec:"enc_shares"`
}

// ComplaintResponseMessage is the message sent by the sharer exposing the shares
// of those who broadcasted a complaint in their original share
type ComplaintResponseMessage struct {
	_struct         struct{}         `codec:",omitempty,omitemptyarray"`
	ComplaintShares []pedersen.Share `codec:"compl_shares"`
}
