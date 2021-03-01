package client

import "github.com/shaih/go-yosovss/communication"

// NetworkBroadcastChannel is the channel a party participating in the
// protocol uses to communicate with the orchestrator server over TCP
type NetworkBroadcastChannel struct {
	ID             int
	SendChannel    chan communication.BroadcastMessage
	ReceiveChannel chan communication.RoundMessages
}

// NewNetworkBroadcastChannel creates a new party to connect with an orchestrator server
func NewNetworkBroadcastChannel(id int) NetworkBroadcastChannel {
	return NetworkBroadcastChannel{
		ID:             id,
		SendChannel:    make(chan communication.BroadcastMessage, 1),
		ReceiveChannel: make(chan communication.RoundMessages, 1),
	}
}

// Send allows for a party to give the orchestrator a message to be broadcasted
// during the round
func (nbc NetworkBroadcastChannel) Send(msg []byte) {
	bcastMsg := communication.BroadcastMessage{
		Payload:  msg,
		SenderID: nbc.ID,
	}

	nbc.SendChannel <- bcastMsg
}

// ReceiveRound is called by a party to get the round number and messages broadcasted by all parties
// in the given round
func (pbc NetworkBroadcastChannel) ReceiveRound() (int, []communication.BroadcastMessage) {
	roundMsgs := <-pbc.ReceiveChannel
	return roundMsgs.Round, []communication.BroadcastMessage(roundMsgs.Messages)
}