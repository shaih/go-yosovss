package main

import (
	"fmt"
	"sync"
	"time"
)

//go:generate msgp

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

// BroadcastChannel represents a means of communication
// between two parties
type BroadcastChannel interface {
	Send(msg []byte)
	ReceiveRound() []BroadcastMessage
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

// StartProtocol initiates the protocol for a party
func (pbc PartyBroadcastChannel) StartProtocol() {
	i := 0
	for {
		time.Sleep(time.Second)
		msg := fmt.Sprintf("Message for round %d from party %d", i, pbc.ID)
		err := pbc.Send([]byte(msg))
		if err != nil {
			fmt.Print(err)
		}
		time.Sleep(time.Second)

		round, roundMsgs, err := pbc.ReceiveRound()
		if err != nil {
			fmt.Print(err)
		}

		var roundMsgsString []string
		for _, roundMsgString := range roundMsgs {
			roundMsgsString = append(roundMsgsString, string(roundMsgString.Payload))
		}

		fmt.Printf("Party %d received messages: %v for round %d\n", pbc.ID, roundMsgsString, round)
		i++
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
	// Create the list of messages to send to all parties
	var msgList []BroadcastMessage
	for _, msg := range o.RoundMsgs {
		msgList = append(msgList, msg)
	}

	roundMsgs := RoundMessages{
		Messages: msgList,
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
