package futurebroadcast

import (
	"log"
	"sync"
	"testing"

	"github.com/shaih/go-yosovss/communication/fake"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/oldvss"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/protocols/resharing/common"
	"github.com/stretchr/testify/assert"
)

func TestResharingProtocolWithFutureBroadcast(t *testing.T) {
	pubKeys, privKeys := curve25519.SetupKeys(12)
	pubSignKeys, privSignKeys := curve25519.SetupSignKeys(12)

	// Hardcoded number of rounds of messaging required for the protocol
	numRounds := 13

	// Create the orchestrator
	o := fake.NewOrchestrator()

	var channels []fake.PartyBroadcastChannel

	// Form initial committees, which are comprised of the ids of the parties that are participating in them
	initCommittees := common.Committees{
		Hold: []int{0, 1, 2},
		Ver:  []int{3, 4, 5},
		FB:   []int{6, 7, 8},
	}

	// Generate a Pedersen share of a message
	msg := pedersen.Message(curve25519.RandomScalar())
	params := pedersen.GenerateParams()
	shares, verifications, _ := oldvss.VSSShare(params, msg, 2, 3)

	reshareParams := common.Params{
		Pks:            pubKeys,
		Psks:           pubSignKeys,
		PedersenParams: params,
		T:              2, // threshold
		N:              3, // committee size
		TotalRounds:    3,
	}

	// Initialize channels and connect with orchestrator
	for i := 0; i < 12; i++ {
		channels = append(channels, fake.NewPartyBroadcastChannel(i))
		o.AddChannel(channels[i])
	}

	var wg sync.WaitGroup

	// Start initial holding committee parties that are given a share
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int, wg *sync.WaitGroup) {
			defer wg.Done()
			err := StartCommitteePartyFB(channels[i], reshareParams, initCommittees, privKeys[i], privSignKeys[i],
				&shares[i], verifications, i)
			assert.Equal(t, nil, err)
		}(i, &wg)
	}

	// Start all other parties that are not given a share
	for i := 3; i < 12; i++ {
		wg.Add(1)
		go func(i int, wg *sync.WaitGroup) {
			defer wg.Done()
			err := StartCommitteePartyFB(channels[i], reshareParams, initCommittees, privKeys[i], privSignKeys[i],
				nil, verifications, i)
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

// TestResharingProtocolWithFutureBroadcastBenchmarking contains code that does benchmarking
// for the resharing protocol with future broadcast. It runs resharing for a single round
// using the value of n specified in the first line
func TestResharingProtocolWithFutureBroadcastBenchmarking(t *testing.T) {

	n := 4

	pubKeys, privKeys := curve25519.SetupKeys(n)
	pubSignKeys, privSignKeys := curve25519.SetupSignKeys(n)

	// Hardcoded number of rounds of messaging required for the protocol
	numRounds := 5

	// Create the orchestrator
	o := fake.NewOrchestrator()

	var channels []fake.PartyBroadcastChannel

	// Form initial committees, which are comprised of the ids of the parties that are participating in them
	initCommittees := common.Committees{
		Hold: make([]int, n),
		Ver:  make([]int, n),
		FB:   make([]int, n),
	}

	for i := 0; i < n; i++ {
		initCommittees.Hold[i] = i
		initCommittees.Ver[i] = i
		initCommittees.FB[i] = i
	}

	// Generate a Pedersen share of a message
	msg := pedersen.Message(curve25519.RandomScalar())
	params := pedersen.GenerateParams()
	shares, verifications, _ := oldvss.VSSShare(params, msg, n/2, n)

	reshareParams := common.Params{
		Pks:            pubKeys,
		Psks:           pubSignKeys,
		PedersenParams: params,
		T:              n / 2, // threshold
		N:              n,     // committee size
		TotalRounds:    1,
	}

	// Initialize channels and connect with orchestrator
	for i := 0; i < n; i++ {
		channels = append(channels, fake.NewPartyBroadcastChannel(i))
		o.AddChannel(channels[i])
	}

	var wg sync.WaitGroup

	// Start initial holding committee parties that are given a share
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int, wg *sync.WaitGroup) {
			defer wg.Done()
			err := StartCommitteePartyFB(channels[i], reshareParams, initCommittees, privKeys[i], privSignKeys[i],
				&shares[i], verifications, i)
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
