package resharing

import (
	"log"
	"sync"
	"testing"

	"github.com/shaih/go-yosovss/communication/fake"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/stretchr/testify/assert"
)

func TestVerificationResharing(t *testing.T) {

}
// TODO: Test two level sharing
func TestCommitteeProtocol(t *testing.T) {
	pubKeys, privKeys := curve25519.SetupKeys(9)

	// Hardcoded number of rounds of the protocol
	numRounds := 5

	// Create the orchestrator
	o := fake.NewOrchestrator()

	var channels []fake.PartyBroadcastChannel
	initHoldCommittee := []int{0, 1, 2}
	initVerCommittee := []int{3, 4, 5}

	// Generate a Pedersen share of a message
	msg := pedersen.Message(curve25519.RandomScalar())
	params := pedersen.GenerateParams()
	shares, verifications, _ := pedersen.VSSShare(params, msg, 2, 3)

	// Initialize channels and connect with orchestrator
	for i := 0; i < 9; i++ {
		channels = append(channels, fake.NewPartyBroadcastChannel(i))
		o.AddChannel(channels[i])
	}

	var wg sync.WaitGroup

	// Start initial holding committee parties
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int, wg *sync.WaitGroup) {
			defer wg.Done()
			err := StartCommitteeParty(channels[i], pubKeys, privKeys[0],
				initHoldCommittee, initVerCommittee, params, &shares[i], verifications, i, 2, 3)
			assert.Equal(t, nil, err)
		}(i, &wg)
	}

	// Start other parties
	for i := 3; i < 9; i++ {
		wg.Add(1)
		go func(i int, wg *sync.WaitGroup) {
			defer wg.Done()
			err := StartCommitteeParty(channels[i], pubKeys, privKeys[0],
				initHoldCommittee, initVerCommittee, params, nil, verifications, i, 2, 3)
			assert.Equal(t, nil, err)
		}(i, &wg)
	}

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
