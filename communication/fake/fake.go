package fake

import (
	"fmt"
	"sync"

	"github.com/shaih/go-yosovss/communication"
)

// Orchestrator simulates a secure broadcast channel
// used for communication between parties
type Orchestrator struct {
	Channels     map[int]PartyBroadcastChannel
	RoundMsgs    map[int]communication.BroadcastMessage
	MessageSizes map[int]int
	Round        int
}

// NewOrchestrator creates a new orchestrator
func NewOrchestrator() Orchestrator {
	return Orchestrator{
		Channels:     make(map[int]PartyBroadcastChannel),
		RoundMsgs:    make(map[int]communication.BroadcastMessage),
		MessageSizes: make(map[int]int),
		Round:        0,
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

	// Code for benchmarking
	//fmt.Printf("receive time: %v \n", time.Now())

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
		o.MessageSizes[bcastMsg.SenderID] += len(bcastMsg.Payload)
	}

	return nil
}

// WaitMessageChannel waits until the indicated channel received a message
// Does not remove the message from the channel, so it can be used later with ReceiveMessages()
func (o Orchestrator) WaitMessageChannel(channel int) {
	msg := <-o.Channels[channel].SendChannel // wait
	o.Channels[channel].SendChannel <- msg   // put back the message
}

func (o Orchestrator) collectRoundMessages() communication.RoundMessages {
	var msgs []communication.BroadcastMessage
	for i := 0; i < len(o.Channels); i++ {
		msgs = append(msgs, o.RoundMsgs[i])
	}
	roundMsgs := communication.RoundMessages{
		Messages: msgs,
		Round:    o.Round,
	}
	return roundMsgs
}

// SendMessageChannels sends the round messages to the indicated channels
// Calling it with a slice [0,...,len(o.Channels)-1] is equivalent to calling Broadcast()
func (o Orchestrator) SendMessageChannels(channels []int) error {
	roundMsgs := o.collectRoundMessages()

	for _, i := range channels {
		o.Channels[i].ReceiveChannel <- roundMsgs
	}
	return nil
}

// Broadcast sends to all parties the messages in the round
func (o Orchestrator) Broadcast() error {
	roundMsgs := o.collectRoundMessages()

	for _, bc := range o.Channels {
		bc.ReceiveChannel <- roundMsgs
	}
	return nil
}

// PartyBroadcastChannel implements communication.BroadcastChannel and is the channel
// a party participating in the protocol uses to communicate with the orchestrator
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
