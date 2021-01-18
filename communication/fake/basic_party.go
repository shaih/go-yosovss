package fake

import (
	"fmt"
	"log"
	"time"

	"github.com/shaih/go-yosovss/communication"
)

// BasicParty is a party that prints when it receives messages
// to test basic functionality of communication
type BasicParty struct {
	ID      int
	Channel PartyBroadcastChannel
}

// NewBasicParty returns a new BasicParty
func NewBasicParty(i int) BasicParty {
	return BasicParty{
		ID:      i,
		Channel: NewPartyBroadcastChannel(i),
	}
}

// GetID returns the ID of the party
func (p BasicParty) GetID() int {
	return p.ID
}

// GetBroadcastChannel returns the channel associated with the party
func (p BasicParty) GetBroadcastChannel() communication.BroadcastChannel {
	return p.Channel
}

// StartProtocol initiates the basic protocol for a party that just broadcasts test messages
func (p BasicParty) StartProtocol(rounds int) error {
	for i := 0; i < rounds; i++ {
		time.Sleep(time.Second)
		msg := fmt.Sprintf("Message for round %d from party %d", i, p.ID)
		p.Channel.Send([]byte(msg))

		time.Sleep(time.Second)

		round, roundMsgs := p.Channel.ReceiveRound()

		var roundMsgsString []string
		for _, roundMsgString := range roundMsgs {
			roundMsgsString = append(roundMsgsString, string(roundMsgString.Payload))
		}

		log.Printf("Party %d received messages: %v for round %d\n", p.ID, roundMsgsString, round)
	}
	return nil
}
