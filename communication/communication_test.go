package communication

import (
	"fmt"
	"log"
	"sync"
	"testing"

	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/pedersen"
)

// setupKeys creates pub-priv keypairs for everyone participating in the protocol
func setupKeys(n int) ([]curve25519.PublicKey, []curve25519.PrivateKey) {
	var pubKeys []curve25519.PublicKey
	var privKeys []curve25519.PrivateKey
	for i := 0; i < n; i++ {
		pk, sk := curve25519.GenerateKeys()
		pubKeys = append(pubKeys, pk)
		privKeys = append(privKeys, sk)
	}

	return pubKeys, privKeys
}

func TestCommuncationProtocol(t *testing.T) {
	fmt.Println("----------Start Communication Protocol Test----------")
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
	var wg sync.WaitGroup

	wg.Add(2)
	go pbc1.StartTestProtocol(numRounds, &wg)
	go pbc2.StartTestProtocol(numRounds, &wg)

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
	fmt.Println("----------Finish Communication Protocol Test----------")
}

func TestVSSProtocol(t *testing.T) {
	fmt.Println("----------Start VSS Protocol Test----------")
	pubKeys, privKeys := setupKeys(4)

	// Hardcoded number of rounds of the protocol
	numRounds := 3

	// Create the orchestrator
	o := NewOrchestrator()

	// Initialize 1 sharer and 3 parties
	sharer := NewPartyBroadcastChannel(0)
	party1 := NewPartyBroadcastChannel(1)
	party2 := NewPartyBroadcastChannel(2)
	party3 := NewPartyBroadcastChannel(3)

	// Connect the two parties with the orchestrator
	o.AddParty(sharer)
	o.AddParty(party1)
	o.AddParty(party2)
	o.AddParty(party3)

	m := pedersen.Message(curve25519.RandomScalar())

	// Start up the parties in the protocol for 2-of-3 Pedersen VSS
	var wg sync.WaitGroup

	wg.Add(4)
	go sharer.StartProtocolSharer(m, pubKeys, privKeys[0], 2, 3, &wg)
	go party1.StartProtocolParty(pubKeys, privKeys[1], 1, 2, 3, &wg)
	go party2.StartProtocolParty(pubKeys, privKeys[2], 2, 2, 3, &wg)
	go party3.StartProtocolParty(pubKeys, privKeys[3], 3, 2, 3, &wg)

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
	fmt.Println("----------Finish VSS Protocol Test----------")
}

func TestVSSProtocolRejectDealer(t *testing.T) {
	fmt.Println("----------Start VSS Protocol Reject Dealer Test----------")
	pubKeys, privKeys := setupKeys(5)

	// Hardcoded number of rounds of the protocol
	numRounds := 3

	// Create the orchestrator
	o := NewOrchestrator()

	// Initialize 1 sharer and 3 parties
	sharer := NewPartyBroadcastChannel(0)
	party1 := NewPartyBroadcastChannel(1)
	party2 := NewPartyBroadcastChannel(2)
	party3 := NewPartyBroadcastChannel(3)
	party4 := NewPartyBroadcastChannel(4)

	// Connect the two parties with the orchestrator
	o.AddParty(sharer)
	o.AddParty(party1)
	o.AddParty(party2)
	o.AddParty(party3)
	o.AddParty(party4)

	m := pedersen.Message(curve25519.RandomScalar())

	// Start up the parties in the protocol for 2-of-4 Pedersen VSS
	var wg sync.WaitGroup

	wg.Add(5)
	go sharer.StartProtocolSharerMalicious(m, pubKeys, privKeys[0], 2, 4, &wg) // A dealer who gives party 2 and party 3 invalid shares
	go party1.StartProtocolParty(pubKeys, privKeys[1], 1, 2, 4, &wg)
	go party2.StartProtocolParty(pubKeys, privKeys[2], 2, 2, 4, &wg)
	go party3.StartProtocolParty(pubKeys, privKeys[3], 3, 2, 4, &wg)
	go party4.StartProtocolParty(pubKeys, privKeys[4], 4, 2, 4, &wg)

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
	fmt.Println("----------Finish VSS Protocol Reject Dealer Test----------")
}
