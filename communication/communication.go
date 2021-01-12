package communication

import (
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"

	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/pedersen"
)

//go:generate msgp
//msgp:ignore SharerMessage

// BroadcastMessage is a wrapper for a message broadcasted by a
// party in the protocol
type BroadcastMessage struct {
	Payload  []byte `msg:"payload"`
	SenderID int    `msg:"sender_id"`
}

// RoundMessages is a wrapper for all the messages send in a round
type RoundMessages struct {
	Messages []BroadcastMessage `msg:"messages"`
	Round    int                `msg:"round"`
}

// PartyBroadcastChannel is the channel a party participating in the
// protocol uses to communicate with the orchestrator
type PartyBroadcastChannel struct {
	ID             int
	SendChannel    chan []byte
	ReceiveChannel chan []byte
}

// Orchestrator simulates a secure broadcast channel
// used for communication between parties
type Orchestrator struct {
	Channels  map[int]PartyBroadcastChannel
	RoundMsgs map[int]BroadcastMessage
	Round     int
}

// SharerMessageWrapper is the raw type of SharerMessage used for msgp
type SharerMessageWrapper struct {
	Params struct {
		G [32]byte `msg:"g"`
		H [32]byte `msg:"h"`
	}
	Verifications   [][32]byte `msg:"verifications"`
	EncryptedShares [][]byte   `msg:"encrypted_shares"`
}

// SharerMessage is the first message broadcasted by the sharer
type SharerMessage struct {
	Params          pedersen.Params
	Verifications   []pedersen.Commitment
	EncryptedShares []curve25519.Ciphertext
}

// ComplaintResponseMessageWrapper is raw type of ComplaintResponseMessage used for msgp
type ComplaintResponseMessageWrapper struct {
	ComplaintShares []struct {
		Index       int      `msg:"index"`
		IndexScalar [32]byte `msg:"index_scalar"`
		S           [32]byte `msg:"s"`
		R           [32]byte `msg:"r"`
	} `msg:"complaint_shares"`
}

// ComplaintResponseMessage is the message sent by the sharer exposing the shares
// of those who broadcasted a complaint in their original share
type ComplaintResponseMessage struct {
	ComplaintShares []pedersen.Share `msg:"complaint_shares"`
}

// NewOrchestrator creates a new orchestrator
func NewOrchestrator() Orchestrator {
	return Orchestrator{
		Channels:  make(map[int]PartyBroadcastChannel),
		RoundMsgs: make(map[int]BroadcastMessage),
		Round:     0,
	}
}

// NewPartyBroadcastChannel creates a new party to connect with an orchestrator
func NewPartyBroadcastChannel(id int) PartyBroadcastChannel {
	return PartyBroadcastChannel{
		ID:             id,
		SendChannel:    make(chan []byte, 1),
		ReceiveChannel: make(chan []byte, 1),
	}
}

// Send allows for a party to give the orchestrator a message to be broadcasted
// during the round
func (pbc PartyBroadcastChannel) Send(msg []byte) error {
	bcastMsg := BroadcastMessage{
		Payload:  msg,
		SenderID: pbc.ID,
	}

	bcastMsgEncoding, err := bcastMsg.MarshalMsg(nil)
	if err != nil {
		return fmt.Errorf("broadcast message encoding failed: %v", err)
	}

	pbc.SendChannel <- bcastMsgEncoding
	return nil
}

// ReceiveRound is called by a party to get the round number and messages broadcasted by all parties
// in the given round
func (pbc PartyBroadcastChannel) ReceiveRound() (int, []BroadcastMessage, error) {
	var roundMsgs RoundMessages
	roundMsgsEncoding := <-pbc.ReceiveChannel
	_, err := roundMsgs.UnmarshalMsg(roundMsgsEncoding)
	if err != nil {
		return 0, nil, fmt.Errorf("Unable to decode round messages: %v", err)
	}

	return roundMsgs.Round, []BroadcastMessage(roundMsgs.Messages), nil
}

// StartTestProtocol initiates the basic protocol for a party that just broadcasts test messages
func (pbc PartyBroadcastChannel) StartTestProtocol(rounds int, wg *sync.WaitGroup) {
	defer wg.Done()

	for i := 0; i < rounds; i++ {
		time.Sleep(time.Second)
		msg := fmt.Sprintf("Message for round %d from party %d", i, pbc.ID)
		err := pbc.Send([]byte(msg))
		if err != nil {
			log.Fatal(err)
		}
		time.Sleep(time.Second)

		round, roundMsgs, err := pbc.ReceiveRound()
		if err != nil {
			log.Fatal(err)
		}

		var roundMsgsString []string
		for _, roundMsgString := range roundMsgs {
			roundMsgsString = append(roundMsgsString, string(roundMsgString.Payload))
		}

		log.Printf("Party %d received messages: %v for round %d\n", pbc.ID, roundMsgsString, round)
	}
}

// StartProtocolSharer intiates the actions of a honest sharer participating in a
// t-of-n Pedersen VSS protocol to share a message m
func (pbc PartyBroadcastChannel) StartProtocolSharer(
	m pedersen.Message,
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	t int,
	n int,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	// Broadcast the verification shares and the encrypted shares
	params := pedersen.GenerateParams()

	shares, verifications, err := pedersen.VSSShare(params, m, t, n)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Sharer created verifications: %v\n", *verifications)
	log.Printf("Sharer created shares: %v\n", *shares)

	var encryptedShares []curve25519.Ciphertext
	for i, share := range *shares {
		// Encode each share as a byte array for encryption
		shareEncoding, err := share.MarshalMsg(nil)
		if err != nil {
			log.Fatalf("Share encoding failed: %v\n", err)
		}

		// Encrypt share i with party i's public key
		c, err := curve25519.Encrypt(publicKeys[i+1], curve25519.Message(shareEncoding))
		if err != nil {
			log.Fatal(err)
		}
		encryptedShares = append(encryptedShares, c)
	}

	sharerMsg := SharerMessage{
		Params:          *params,
		Verifications:   *verifications,
		EncryptedShares: encryptedShares,
	}

	sharerMsgEncoding, err := sharerMsg.Marshal()
	if err != nil {
		log.Fatalf("Sharer message encoding failed: %v\n", err)
	}

	// Broadcast verifications and shares
	err = pbc.Send(sharerMsgEncoding)
	if err != nil {
		log.Fatal(err)
	}

	_, _, err = pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}

	// Does not send for complaint round
	err = pbc.Send([]byte{})
	if err != nil {
		log.Fatal(err)
	}

	// Receive potential complaints from parties
	_, roundMsgs, err := pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}

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

	complaintResponseMsgEncoding, err := complaintResponseMsg.Marshal()
	if err != nil {
		log.Fatalf("complaint response encoding failed: %v\n", err)
	}
	// Publish the shares of those who complained
	err = pbc.Send(complaintResponseMsgEncoding)
	if err != nil {
		log.Fatal(err)
	}

	_, _, err = pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}
}

// StartProtocolSharerMalicious intiates the actions of a dishonest sharer
// participating in a t-of-n Pedersen VSS protocol to share a message m
func (pbc PartyBroadcastChannel) StartProtocolSharerMalicious(
	m pedersen.Message,
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	t int,
	n int,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	// Broadcast the verification shares and the encrypted shares
	params := pedersen.GenerateParams()

	shares, verifications, err := pedersen.VSSShare(params, m, t, n)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Sharer created verifications: %v\n", *verifications)
	log.Printf("Sharer created shares: %v\n", *shares)

	var encryptedShares []curve25519.Ciphertext

	// Maliciously modify some shares
	(*shares)[1].S = curve25519.RandomScalar()
	(*shares)[2].R = curve25519.RandomScalar()

	for i, share := range *shares {
		// Encode each share as a byte array for encryption
		shareEncoding, err := share.MarshalMsg(nil)
		if err != nil {
			log.Fatalf("Share encoding failed: %v\n", err)
		}

		// Encrypt share i with party i's public key
		c, err := curve25519.Encrypt(publicKeys[i+1], curve25519.Message(shareEncoding))
		if err != nil {
			log.Fatal(err)
		}
		encryptedShares = append(encryptedShares, c)
	}

	sharerMsg := SharerMessage{
		Params:          *params,
		Verifications:   *verifications,
		EncryptedShares: encryptedShares,
	}

	sharerMsgEncoding, err := sharerMsg.Marshal()
	if err != nil {
		log.Fatalf("Sharer message encoding failed: %v\n", err)
	}

	// Broadcast verifications and shares
	err = pbc.Send(sharerMsgEncoding)
	if err != nil {
		log.Fatal(err)
	}

	_, _, err = pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}

	// Does not send for complaint round
	err = pbc.Send([]byte{})
	if err != nil {
		log.Fatal(err)
	}

	// Receive potential complaints from parties
	_, roundMsgs, err := pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}

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

	complaintResponseMsgEncoding, err := complaintResponseMsg.Marshal()
	if err != nil {
		log.Fatalf("complaint response encoding failed: %v\n", err)
	}

	// Publish the shares of those who complained
	err = pbc.Send(complaintResponseMsgEncoding)
	if err != nil {
		log.Fatal(err)
	}

	_, _, err = pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}
}

// StartProtocolParty initiates the protocol for party i participating in a t-of-n Pedersen VSS protocol
func (pbc PartyBroadcastChannel) StartProtocolParty(
	publicKeys []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	i int,
	t int,
	n int,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	rejectDealer := false

	// Doesn't send anything first round
	err := pbc.Send([]byte{})
	if err != nil {
		log.Fatal(err)
	}

	// Receive verifications and shares
	_, roundMsgs, err := pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}

	var sharerMsg SharerMessage
	sharerMsg, err = UnmarshalSharerMessage(roundMsgs[0].Payload)
	if err != nil {
		log.Fatalf("sharer message decoding failed: %v\n", err)
	}

	// Decrypt the share meant for party i
	shareEncoding, err := curve25519.Decrypt(publicKeys[i], sk, sharerMsg.EncryptedShares[i-1])
	if err != nil {
		log.Fatalf("share decryption failed for party %d: %v\n", i, err)
	}

	// Decode the share
	var share pedersen.Share
	_, err = share.UnmarshalMsg(shareEncoding)
	if err != nil {
		log.Fatalf("share decoding for party %d: %v\n", i, err)
	}

	log.Printf("Party %d decrypted share: %v\n", i, share)

	// Check the share and broadcast a complaint if it did not verify
	isValidShare, err := pedersen.VSSVerify(&sharerMsg.Params, share, sharerMsg.Verifications)
	if err != nil {
		log.Fatal(err)
	}

	if isValidShare {
		err = pbc.Send([]byte{})
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("Party %d broadcasted a share complaint\n", i)
		err = pbc.Send([]byte{1}) // Non-zero length complaint message
		if err != nil {
			log.Fatal(err)
		}
	}

	// Get all the complaint messages broadcasted
	_, roundMsgs, err = pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}

	complaints := make(map[int]*pedersen.Share)

	for j, roundMsg := range roundMsgs {
		if len(roundMsg.Payload) > 0 {
			complaints[j] = nil
		}
	}

	// Get the sharer's response to the broadcasted complaints
	err = pbc.Send([]byte{})
	if err != nil {
		log.Fatal(err)
	}

	_, roundMsgs, err = pbc.ReceiveRound()
	if err != nil {
		log.Fatal(err)
	}

	var complaintResponseMsg ComplaintResponseMessage
	complaintResponseMsg, err = UnmarshalComplaintResponseMessage(roundMsgs[0].Payload)
	if err != nil {
		log.Fatalf("complaint responses decoding failed for party %d: %v\n", i, err)
	}

	// Check and each share broadcasted by the sharer
	for _, share := range complaintResponseMsg.ComplaintShares {
		if _, ok := complaints[share.Index]; ok {
			isValidShare, err = pedersen.VSSVerify(&sharerMsg.Params, share, sharerMsg.Verifications)
			if err != nil {
				log.Fatalf("complaint share verification failed for party %d: %v\n", i, err)
			}

			// Reject dealer if a share is invalid
			if !isValidShare {
				log.Printf("Party %d rejects the dealer for invalid share %d\n", i, share.Index)
				rejectDealer = true
				break
			}

			complaints[share.Index] = &share
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

}

// AddParty connects a party to the orchestrator to participate in the protocol
func (o Orchestrator) AddParty(pbc PartyBroadcastChannel) {
	o.Channels[pbc.ID] = pbc
}

// PartyBroadcastChannel gets the party specified by the id
func (o Orchestrator) PartyBroadcastChannel(id int) (*PartyBroadcastChannel, error) {
	pbc, ok := o.Channels[id]
	if !ok {
		return nil, fmt.Errorf("channel not found for id: %d", id)
	}
	return &pbc, nil
}

// ReceiveMessages is used by the orchestrator to collect messages from all parties
// in a given round
func (o Orchestrator) ReceiveMessages() error {
	// Simultaneously listen to channels opened with the parties
	agg := make(chan []byte, len(o.Channels))
	var wg sync.WaitGroup
	for _, pbc := range o.Channels {
		wg.Add(1)
		go func(c chan []byte, wg *sync.WaitGroup) {
			defer wg.Done()
			msg := <-c
			agg <- msg
		}(pbc.SendChannel, &wg)
	}

	wg.Wait()

	// Iterate through all the received messages
	for i := 0; i < len(o.Channels); i++ {
		bcastMsgEncoding := <-agg
		var bcastMsg BroadcastMessage
		_, err := bcastMsg.UnmarshalMsg(bcastMsgEncoding)
		if err != nil {
			return fmt.Errorf("broadcast message decoding failed: %v", err)
		}
		o.RoundMsgs[bcastMsg.SenderID] = bcastMsg
	}

	return nil
}

// Broadcast sends to all parties the messages in the round
func (o Orchestrator) Broadcast() error {
	var msgs []BroadcastMessage
	for i := 0; i < len(o.Channels); i++ {
		msgs = append(msgs, o.RoundMsgs[i])
	}
	roundMsgs := RoundMessages{
		Messages: msgs,
		Round:    o.Round,
	}

	roundMsgsEncoding, err := roundMsgs.MarshalMsg(nil)
	if err != nil {
		return fmt.Errorf("round messages encoding failed: %v", err)
	}

	for _, pbc := range o.Channels {
		pbc.ReceiveChannel <- roundMsgsEncoding
	}

	return nil
}

// Marshal performs the appropriate type conversion to marshal a SharerMessage
// using msgp
func (sharerMsg SharerMessage) Marshal() ([]byte, error) {
	shareMsgWrapper := *(*SharerMessageWrapper)(unsafe.Pointer(&sharerMsg))
	return shareMsgWrapper.MarshalMsg(nil)
}

// UnmarshalSharerMessage performs the appropriate type conversion to unmarshal a SharerMessage
// using msgp
func UnmarshalSharerMessage(sharerMsgEncoding []byte) (SharerMessage, error) {
	var sharerMsgWrapper SharerMessageWrapper
	_, err := sharerMsgWrapper.UnmarshalMsg(sharerMsgEncoding)
	sharerMsg := *(*SharerMessage)(unsafe.Pointer(&sharerMsgWrapper))
	return sharerMsg, err
}

// Marshal performs the appropriate type conversion to marshal a ComplaintResponseMessage
// using msgp
func (complaintResponseMsg ComplaintResponseMessage) Marshal() ([]byte, error) {
	complaintResponseMsgWrapper := *(*ComplaintResponseMessageWrapper)(unsafe.Pointer(&complaintResponseMsg))
	return complaintResponseMsgWrapper.MarshalMsg(nil)
}

// UnmarshalComplaintResponseMessage performs the appropriate type conversion to unmarshal a ComplaintResponseMessage
// using msgp
func UnmarshalComplaintResponseMessage(complaintResponseMsgEncoding []byte) (ComplaintResponseMessage, error) {
	var complaintResponseMsgWrapper ComplaintResponseMessageWrapper
	_, err := complaintResponseMsgWrapper.UnmarshalMsg(complaintResponseMsgEncoding)
	complaintResponseMsg := *(*ComplaintResponseMessage)(unsafe.Pointer(&complaintResponseMsgWrapper))
	return complaintResponseMsg, err
}
