package main

import "log"

func main() {

	// Hardcoded number of rounds of the protocol
	numRounds := 5

	// Create the orchestrator
	o := NewOrchestrator()

	// Initialize two parties and create the two broadcast channels for the 2 parties
	pbc1 := NewPartyBroadcastChannel(1)
	pbc2 := NewPartyBroadcastChannel(2)

	// Connect the two parties with the orchestrator
	o.AddParty(pbc1)
	o.AddParty(pbc2)

	// Start up the parties in the protocol
	go pbc1.StartProtocol()
	go pbc2.StartProtocol()

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
}
