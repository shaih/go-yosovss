package vss

import (
	"log"
	"sync"
	"testing"

	"github.com/shaih/go-yosovss/communication/fake"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/stretchr/testify/assert"
)

func TestVSSProtocol(t *testing.T) {
	pubKeys, privKeys := curve25519.SetupKeys(4)

	// Hardcoded number of rounds of the protocol
	numRounds := 3

	// Create the orchestrator
	o := fake.NewOrchestrator()

	// Initialize 1 sharer and 3 parties
	dealer := fake.NewPartyBroadcastChannel(0)
	party1 := fake.NewPartyBroadcastChannel(1)
	party2 := fake.NewPartyBroadcastChannel(2)
	party3 := fake.NewPartyBroadcastChannel(3)

	// Connect the two parties with the orchestrator
	o.AddChannel(dealer)
	o.AddChannel(party1)
	o.AddChannel(party2)
	o.AddChannel(party3)

	m := pedersen.Message(curve25519.RandomScalar())

	// Start up the parties in the protocol for 2-of-3 Pedersen VSS
	var wg sync.WaitGroup

	wg.Add(4)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSDealer(dealer, m, pubKeys, privKeys[0], 2, 3)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSParty(party1, pubKeys, privKeys[1], 1, 2, 3)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSParty(party2, pubKeys, privKeys[2], 2, 2, 3)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSParty(party3, pubKeys, privKeys[3], 3, 2, 3)
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

func TestVSSProtocolRejectDealer(t *testing.T) {
	pubKeys, privKeys := curve25519.SetupKeys(5)

	// Hardcoded number of rounds of the protocol
	numRounds := 3

	// Create the orchestrator
	o := fake.NewOrchestrator()

	// Initialize 1 sharer and 4 parties
	dealer := fake.NewPartyBroadcastChannel(0)
	party1 := fake.NewPartyBroadcastChannel(1)
	party2 := fake.NewPartyBroadcastChannel(2)
	party3 := fake.NewPartyBroadcastChannel(3)
	party4 := fake.NewPartyBroadcastChannel(4)

	// Connect the two parties with the orchestrator
	o.AddChannel(dealer)
	o.AddChannel(party1)
	o.AddChannel(party2)
	o.AddChannel(party3)
	o.AddChannel(party4)

	m := pedersen.Message(curve25519.RandomScalar())

	// Start up the parties in the protocol for 2-of-4 Pedersen VSS
	var wg sync.WaitGroup

	wg.Add(5)
	// A dealer who gives party 2 and party 3 invalid shares
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSMaliciousDealer(dealer, m, pubKeys, privKeys[0], 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSParty(party1, pubKeys, privKeys[1], 1, 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSParty(party2, pubKeys, privKeys[2], 2, 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSParty(party3, pubKeys, privKeys[3], 3, 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := StartPedersenVSSParty(party4, pubKeys, privKeys[4], 4, 2, 4)
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
