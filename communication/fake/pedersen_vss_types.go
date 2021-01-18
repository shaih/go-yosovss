package fake

import (
	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/pedersen"
)

// SharerMessage is the first message broadcasted by the sharer
type SharerMessage struct {
	Params          pedersen.Params
	Verifications   []pedersen.Commitment
	EncryptedShares []curve25519.Ciphertext
}

// ComplaintResponseMessage is the message sent by the sharer exposing the shares
// of those who broadcasted a complaint in their original share
type ComplaintResponseMessage struct {
	ComplaintShares []pedersen.Share `msg:"complaint_shares"`
}
