package fake

import (
	"fmt"
	"log"

	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/encoding"
	"github.com/shaih/go-yosovss/pedersen"
)

// PedersenVSSDealer is a party that shares a secret in the Pedersen
// VSS protocol
type PedersenVSSDealer struct {
	ID      int
	Channel PartyBroadcastChannel
}

// NewPedersenVSSDealer returns a new PedersenVSSDealer
func NewPedersenVSSDealer(i int) PedersenVSSDealer {
	return PedersenVSSDealer{
		ID:      i,
		Channel: NewPartyBroadcastChannel(i),
	}
}

// GetID returns the ID of the party
func (p PedersenVSSDealer) GetID() int {
	return p.ID
}

// GetBroadcastChannel returns the channel associated with the party
func (p PedersenVSSDealer) GetBroadcastChannel() communication.BroadcastChannel {
	return p.Channel
}

// StartProtocol intiates the actions of a honest sharer participating in a
// t-of-n Pedersen VSS protocol to share a message m
func (p PedersenVSSDealer) StartProtocol(
	m pedersen.Message,
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	t int,
	n int,
) error {
	// Broadcast the verification shares and the encrypted shares
	params := pedersen.GenerateParams()

	shares, verifications, err := pedersen.VSSShare(params, m, t, n)
	if err != nil {
		return fmt.Errorf("Pedersen VSS share operation failed: %v", err)
	}

	log.Printf("Sharer created verifications: %v\n", *verifications)
	log.Printf("Sharer created shares: %v\n", *shares)

	var encryptedShares []curve25519.Ciphertext
	for i, share := range *shares {
		// Encode each share as a byte array for encryption
		shareEncoding := encoding.EncodeReflect(share)

		// Encrypt share i with party i's public key
		c, err := curve25519.Encrypt(publicKeys[i+1], curve25519.Message(shareEncoding))
		if err != nil {
			return fmt.Errorf("Failed to encrypt shares: %v", err)
		}
		encryptedShares = append(encryptedShares, c)
	}

	sharerMsg := SharerMessage{
		Params:          *params,
		Verifications:   *verifications,
		EncryptedShares: encryptedShares,
	}

	// Broadcast verifications and shares
	p.Channel.Send(encoding.EncodeReflect(sharerMsg))
	p.Channel.ReceiveRound()

	// Does not send for complaint round
	p.Channel.Send([]byte{})

	// Receive potential complaints from parties
	_, roundMsgs := p.Channel.ReceiveRound()

	// Collect shares of those who complained
	var complaintShares []pedersen.Share
	for i, roundMsg := range roundMsgs {
		if len(roundMsg.Payload) > 0 {
			complaintShares = append(complaintShares, (*shares)[i])
		}
	}

	complaintResponseMsg := ComplaintResponseMessage{
		ComplaintShares: complaintShares,
	}

	// Publish the shares of those who complained
	p.Channel.Send(encoding.EncodeReflect(complaintResponseMsg))
	p.Channel.ReceiveRound()

	return nil
}
