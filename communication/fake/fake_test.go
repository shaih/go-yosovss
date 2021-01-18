package fake

import (
	"fmt"
	"log"
	"sync"
	"testing"

	"github.com/shaih/go-yosovss/curve25519"
	"github.com/shaih/go-yosovss/pedersen"
	"github.com/stretchr/testify/assert"
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
	p1 := NewBasicParty(1)
	p2 := NewBasicParty(2)

	// Connect the two parties with the orchestrator
	o.AddChannel(p1.Channel)
	o.AddChannel(p2.Channel)

	// Start up the parties in the protocol
	var wg sync.WaitGroup

	wg.Add(2)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := p1.StartProtocol(numRounds)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := p2.StartProtocol(numRounds)
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
	sharer := NewPedersenVSSDealer(0)
	party1 := NewPedersenVSSParty(1)
	party2 := NewPedersenVSSParty(2)
	party3 := NewPedersenVSSParty(3)

	// Connect the two parties with the orchestrator
	o.AddChannel(sharer.Channel)
	o.AddChannel(party1.Channel)
	o.AddChannel(party2.Channel)
	o.AddChannel(party3.Channel)

	m := pedersen.Message(curve25519.RandomScalar())

	// Start up the parties in the protocol for 2-of-3 Pedersen VSS
	var wg sync.WaitGroup

	wg.Add(4)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := sharer.StartProtocol(m, pubKeys, privKeys[0], 2, 3)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := party1.StartProtocol(pubKeys, privKeys[1], 1, 2, 3)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := party2.StartProtocol(pubKeys, privKeys[2], 2, 2, 3)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := party3.StartProtocol(pubKeys, privKeys[3], 3, 2, 3)
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
	fmt.Println("----------Finish VSS Protocol Test----------")
}

func TestVSSProtocolRejectDealer(t *testing.T) {
	fmt.Println("----------Start VSS Protocol Reject Dealer Test----------")
	pubKeys, privKeys := setupKeys(5)

	// Hardcoded number of rounds of the protocol
	numRounds := 3

	// Create the orchestrator
	o := NewOrchestrator()

	// Initialize 1 sharer and 4 parties
	sharer := NewPedersenVSSDealerMalicious(0)
	party1 := NewPedersenVSSParty(1)
	party2 := NewPedersenVSSParty(2)
	party3 := NewPedersenVSSParty(3)
	party4 := NewPedersenVSSParty(4)

	// Connect the two parties with the orchestrator
	o.AddChannel(sharer.Channel)
	o.AddChannel(party1.Channel)
	o.AddChannel(party2.Channel)
	o.AddChannel(party3.Channel)
	o.AddChannel(party4.Channel)

	m := pedersen.Message(curve25519.RandomScalar())

	// Start up the parties in the protocol for 2-of-4 Pedersen VSS
	var wg sync.WaitGroup

	wg.Add(5)
	// A dealer who gives party 2 and party 3 invalid shares
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := sharer.StartProtocol(m, pubKeys, privKeys[0], 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := party1.StartProtocol(pubKeys, privKeys[1], 1, 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := party2.StartProtocol(pubKeys, privKeys[2], 2, 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := party3.StartProtocol(pubKeys, privKeys[3], 3, 2, 4)
		assert.Equal(t, nil, err)
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		err := party4.StartProtocol(pubKeys, privKeys[4], 4, 2, 4)
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
	fmt.Println("----------Finish VSS Protocol Reject Dealer Test----------")
}
