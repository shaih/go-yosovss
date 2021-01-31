package fake

import (
	"log"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommuncationProtocol(t *testing.T) {
	// Hardcoded number of rounds of the protocol
	numRounds := 5

	// Create the orchestrator
	o := NewOrchestrator()

	// Initialize two parties and create the two broadcast channels for the 2 parties
	p1 := NewPartyBroadcastChannel(1)
	p2 := NewPartyBroadcastChannel(2)

	// Connect the two parties with the orchestrator
	o.AddChannel(p1)
	o.AddChannel(p2)

	// Start up the parties in the protocol
	var wg sync.WaitGroup

	wg.Add(2)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := parties.StartTestParty(p1, numRounds)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := parties.StartTestParty(p2, numRounds)
		assert.Equal(t, nil, err)
	}(&wg)

	// Simulate the protocol for a fixed number of rounds
	// Naively switches rounds whenever every party has sent a message
	for o.Round < numRounds {
		err := o.ReceiveMessages()
		if err != nil {
			log.Fatal(err)
		}
		err = o.Broadcast()
		if err != nil {
			log.Fatal(err)
		}
		o.Round++
	}

	wg.Wait()
}
