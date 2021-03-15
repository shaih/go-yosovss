package vss

import (
	"fmt"
	"github.com/shaih/go-yosovss/communication"
	"log"

	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// StartPedersenVSSDealer initiates the actions of a honest dealer participating in a
// t-of-n Pedersen VSS protocol to share a message m
func StartPedersenVSSDealer(
	bc communication.BroadcastChannel,
	m pedersen.Message,
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	t int,
	n int,
) error {
	// Broadcast the verification shares and the encrypted shares
	params := pedersen.GenerateParams()

	shares, verifications, err := pedersen.VSSShare(*params, m, t, n)
	if err != nil {
		return fmt.Errorf("Pedersen VSS share operation failed: %v", err)
	}

	log.Printf("Sharer created verifications: %v\n", verifications)
	log.Printf("Sharer created shares: %v\n", shares)

	var encryptedShares []curve25519.Ciphertext
	for i, share := range shares {
		// Encode each share as a byte array for encryption

		shareEncoding := msgpack.Encode(share)

		// Encrypt share i with party i's public key
		c, err := curve25519.Encrypt(publicKeys[i+1], curve25519.Message(shareEncoding))
		if err != nil {
			return fmt.Errorf("failed to encrypt shares: %v", err)
		}
		encryptedShares = append(encryptedShares, c)
	}

	sharerMsg := SharerMessage{
		Params:          *params,
		Verifications:   verifications,
		EncryptedShares: encryptedShares,
	}

	// Broadcast verifications and shares
	bc.Send(msgpack.Encode(sharerMsg))
	bc.ReceiveRound()

	// Does not send for complaint round
	bc.Send([]byte{})

	// Receive potential complaints from parties
	_, roundMsgs := bc.ReceiveRound()

	// Collect shares of those who complained
	var complaintShares []pedersen.Share
	for i, roundMsg := range roundMsgs {
		if len(roundMsg.Payload) > 0 {
			complaintShares = append(complaintShares, shares[i])
		}
	}

	complaintResponseMsg := ComplaintResponseMessage{
		ComplaintShares: complaintShares,
	}

	// Publish the shares of those who complained
	bc.Send(msgpack.Encode(complaintResponseMsg))
	bc.ReceiveRound()

	return nil
}
