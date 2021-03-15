package network

import (
	"fmt"
	"github.com/shaih/go-yosovss/communication"
	"sync"
)

// Orchestrator simulates a secure broadcast channel
// used for communication between parties
type Orchestrator struct {
	Channels  map[int]PartyBroadcastChannel
	RoundMsgs map[int]communication.BroadcastMessage
	Round     int
}

// NewOrchestrator creates a new orchestrator
func NewOrchestrator() Orchestrator {
	return Orchestrator{
		Channels:  make(map[int]PartyBroadcastChannel),
		RoundMsgs: make(map[int]communication.BroadcastMessage),
		Round:     0,
	}
}

// AddChannel connects a party's channel to the orchestrator to participate in the protocol
func (o Orchestrator) AddChannel(pbc PartyBroadcastChannel) {
	o.Channels[pbc.ID] = pbc
}

// BroadcastChannel gets the party specified by the id
func (o Orchestrator) BroadcastChannel(id int) (*PartyBroadcastChannel, error) {
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
	agg := make(chan communication.BroadcastMessage, len(o.Channels))
	var wg sync.WaitGroup
	for _, pbc := range o.Channels {
		wg.Add(1)
		go func(c chan communication.BroadcastMessage, wg *sync.WaitGroup) {
			defer wg.Done()
			msg := <-c
			agg <- msg
		}(pbc.SendChannel, &wg)
	}

	wg.Wait()

	// Iterate through all the received messages
	for i := 0; i < len(o.Channels); i++ {
		bcastMsg := <-agg
		o.RoundMsgs[bcastMsg.SenderID] = bcastMsg
	}

	return nil
}

// Broadcast sends to all parties the messages in the round
func (o Orchestrator) Broadcast() error {
	var msgs []communication.BroadcastMessage
	for i := 0; i < len(o.Channels); i++ {
		msgs = append(msgs, o.RoundMsgs[i])
	}
	roundMsgs := communication.RoundMessages{
		Messages: msgs,
		Round:    o.Round,
	}

	for _, bc := range o.Channels {
		bc.ReceiveChannel <- roundMsgs
	}

	return nil
}

// PartyBroadcastChannel is the channel a party participating in the
// protocol uses to communicate with the orchestrator
type PartyBroadcastChannel struct {
	ID             int
	SendChannel    chan communication.BroadcastMessage
	ReceiveChannel chan communication.RoundMessages
}

// NewPartyBroadcastChannel creates a new party to connect with an orchestrator
func NewPartyBroadcastChannel(id int) PartyBroadcastChannel {
	return PartyBroadcastChannel{
		ID:             id,
		SendChannel:    make(chan communication.BroadcastMessage, 1),
		ReceiveChannel: make(chan communication.RoundMessages, 1),
	}
}

// Send allows for a party to give the orchestrator a message to be broadcasted
// during the round
func (pbc PartyBroadcastChannel) Send(msg []byte) {
	bcastMsg := communication.BroadcastMessage{
		Payload:  msg,
		SenderID: pbc.ID,
	}

	pbc.SendChannel <- bcastMsg
}

// ReceiveRound is called by a party to get the round number and messages broadcasted by all parties
// in the given round
func (pbc PartyBroadcastChannel) ReceiveRound() (int, []communication.BroadcastMessage) {
	roundMsgs := <-pbc.ReceiveChannel
	return roundMsgs.Round, []communication.BroadcastMessage(roundMsgs.Messages)
}

