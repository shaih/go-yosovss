package vss

import (
	"fmt"
	"github.com/shaih/go-yosovss/communication"
	"log"

	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// StartPedersenVSSParty initiates the protocol for party i participating in a t-of-n Pedersen VSS protocol
func StartPedersenVSSParty(
	bc communication.BroadcastChannel,
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	i int,
	t int,
	n int,
) error {
	rejectDealer := false

	// Doesn't send anything first round
	bc.Send([]byte{})

	// Receive verifications and shares
	_, roundMsgs := bc.ReceiveRound()

	var sharerMsg SharerMessage
	err := msgpack.Decode(roundMsgs[0].Payload, &sharerMsg)
	if err != nil {
		return fmt.Errorf("sharer message decoding failed for party %d: %v", i, err)
	}

	// Decrypt the share meant for party i
	shareEncoding, err := curve25519.Decrypt(publicKeys[i], sk, sharerMsg.EncryptedShares[i-1])
	if err != nil {
		return fmt.Errorf("share decryption failed for party %d: %v", i, err)
	}

	// Decode the share
	var share pedersen.Share
	err = msgpack.Decode(shareEncoding, &share)
	if err != nil {
		return fmt.Errorf("decoding share failed for party %d: %v", i, err)
	}

	log.Printf("Party %d decrypted share: %v\n", i, share)

	// Check the share and broadcast a complaint if it did not verify
	isValidShare, err := pedersen.VSSVerify(&sharerMsg.Params, share, sharerMsg.Verifications)
	if err != nil {
		log.Fatal(err)
	}

	if isValidShare {
		bc.Send([]byte{})
	} else {
		log.Printf("Party %d broadcasted a share complaint\n", i)
		bc.Send([]byte{1}) // Non-zero length complaint message
	}

	// Get all the complaint messages broadcasted
	_, roundMsgs = bc.ReceiveRound()

	complaints := make(map[int]*pedersen.Share)

	for j, roundMsg := range roundMsgs {
		if len(roundMsg.Payload) > 0 {
			complaints[j] = nil
		}
	}

	// Get the sharer's response to the broadcasted complaints
	bc.Send([]byte{})

	_, roundMsgs = bc.ReceiveRound()

	var complaintResponseMsg ComplaintResponseMessage
	err = msgpack.Decode(roundMsgs[0].Payload, &complaintResponseMsg)
	if err != nil {
		return fmt.Errorf("complaint responses decoding failed for party %d: %v", i, err)
	}

	// Check and each share broadcasted by the sharer
	for j, share := range complaintResponseMsg.ComplaintShares {
		if _, ok := complaints[share.Index]; ok {
			isValidShare, err = pedersen.VSSVerify(&sharerMsg.Params, share, sharerMsg.Verifications)
			if err != nil {
				return fmt.Errorf("complaint share verification failed for party %d: %v", i, err)
			}

			// Reject dealer if a share is invalid
			if !isValidShare {
				log.Printf("Party %d rejects the dealer for invalid share %d\n", i, share.Index)
				rejectDealer = true
				break
			}

			complaints[share.Index] = &complaintResponseMsg.ComplaintShares[j]
		}
	}

	if !rejectDealer {
		for j, share := range complaints {
			// Reject dealer for not providing response to a complaint
			if share == nil {
				log.Printf("Party %d rejects the dealer for not responding to complaint %d\n", i, j)
				rejectDealer = true
				break
			}
		}
	}

	if !rejectDealer {
		log.Printf("Party %d accepts the secret sharing\n", i)
	}
	return nil
}
