package parties

import (
	"fmt"
	"log"
	"time"

	"github.com/shaih/go-yosovss/communication/fake"
)

// StartTestParty initiates the basic protocol for a party that just broadcasts test messages
func StartTestParty(
	pbc fake.PartyBroadcastChannel,
	rounds int,
) error {
	for i := 0; i < rounds; i++ {
		time.Sleep(time.Second)
		msg := fmt.Sprintf("Message for round %d from party %d", i, pbc.ID)
		pbc.Send([]byte(msg))

		round, roundMsgs := pbc.ReceiveRound()

		var roundMsgsString []string
		for _, roundMsgString := range roundMsgs {
			roundMsgsString = append(roundMsgsString, string(roundMsgString.Payload))
		}

		log.Printf("Party %d received messages: %v for round %d\n", pbc.ID, roundMsgsString, round)
	}
	return nil
}
