package auditor

import (
	"fmt"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

var RoundNames = []string{"dealing", "verification", "resolution", "witness", "auditing", "refreshing"}

func TestResharingProtocolBenchmark(t *testing.T) {
	// Test resharing protocol when everybody is honest
	// with some benchmarking
	// This test runs all parties at once

	var err error

	// Disable logging for efficiency
	originalLogLevel := log.GetLevel()
	log.SetLevel(log.ErrorLevel)

	require := require.New(t)

	const (
		// DO NOT FORGET TO SET BACK TO tt=3 TO ALLOW normal testing to be fast enough
		tt         = 3        // threshold of malicious parties
		n          = 2*tt + 1 // number of parties per committee
		numParties = n        // total number of parties
	)

	fmt.Printf("TestResharingProtocolBenchmark: n=%d, t=%d\n", n, tt)

	pub, prvs, o, secret, rnd := setupResharingSame(t, n, tt)

	// Output of all parties
	outputCommitments := make([][]pedersen.Commitment, numParties)
	outputShares := make([]*vss.Share, numParties)

	var wg sync.WaitGroup

	lastTime := time.Now()

	// Start protocol
	for party := 0; party < numParties; party++ {
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err = StartCommitteeParty(pub, &prvs[party])
			require.NoError(err)
		}(party, &wg)
	}

	// Simulate the protocol for a fixed number of rounds
	// Naively switches rounds whenever every party has sent a message
	for o.Round < numRounds {
		err := o.ReceiveMessages()
		require.NoError(err)

		d := time.Since(lastTime)
		fmt.Printf("Round %d (%-12s) took %fs\n", o.Round, RoundNames[o.Round], d.Seconds())
		lastTime = time.Now()

		err = o.Broadcast()
		require.NoError(err)
		o.Round++
	}

	// Wait for all go routines to finish
	wg.Wait()

	d := time.Since(lastTime)
	fmt.Printf("Round %d (%-12s) took %fs\n", o.Round, RoundNames[o.Round], d.Seconds())
	lastTime = time.Now()

	// Check the results
	checkProtocolResults(
		t,
		pub,
		secret,
		rnd,
		outputCommitments,
		outputShares,
	)

	// Reset log level
	log.SetLevel(originalLogLevel)
}

func TestResharingProtocolBenchmarkParty0(t *testing.T) {
	// Test resharing protocol when everybody is honest
	// with some benchmarking
	// This test makes sure party 0 is run first and benchmark it individually
	// to get a better timing for a single party
	var err error

	// Disable logging for efficiency
	originalLogLevel := log.GetLevel()
	log.SetLevel(log.ErrorLevel)

	require := require.New(t)

	const (
		// DO NOT FORGET TO SET BACK TO tt=3 TO ALLOW normal testing to be fast enough
		tt         = 64       // threshold of malicious parties
		n          = 2*tt + 1 // number of parties per committee
		numParties = n        // total number of parties
	)

	fmt.Printf("TestResharingProtocolBenchmarkParty0: n=%d, t=%d\n", n, tt)

	pub, prvs, o, secret, rnd := setupResharingSame(t, n, tt)

	// Output of all parties
	outputCommitments := make([][]pedersen.Commitment, numParties)
	outputShares := make([]*vss.Share, numParties)

	var wg sync.WaitGroup

	lastTime := time.Now()

	// Start protocol for party 0
	party0done := make(chan bool)
	{
		party := 0
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err = StartCommitteeParty(pub, &prvs[party])
			require.NoError(err)
			party0done <- true
		}(party, &wg)
	}

	// Wait for party 0 message and time it
	o.WaitMessageChannel(0)
	d := time.Since(lastTime)
	fmt.Printf("Round %d (%-12s) took %fs for party 0\n", o.Round, RoundNames[o.Round], d.Seconds())
	lastTime = time.Now()

	// Start protocol for other parties
	for party := 1; party < numParties; party++ {
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err = StartCommitteeParty(pub, &prvs[party])
			require.NoError(err)
		}(party, &wg)
	}

	// Simulate the protocol for a fixed number of rounds
	// Naively switches rounds whenever every party has sent a message
	for o.Round < numRounds {
		err := o.ReceiveMessages()
		require.NoError(err)

		// Time other parties
		d := time.Since(lastTime)
		fmt.Printf("Round %d (%-12s) took %fs for the other parties\n", o.Round, RoundNames[o.Round], d.Seconds())
		lastTime = time.Now()

		// Send message only to party 0 to time it
		err = o.SendMessageChannels([]int{0})
		require.NoError(err)

		// Time party 0
		if o.Round < numRounds-1 {
			// there is still a round after
			o.WaitMessageChannel(0)
		} else {
			// this is the last round, waiting for party 0 to finish
			<-party0done
		}
		d = time.Since(lastTime)
		fmt.Printf("Round %d (%-12s) took %fs for party 0\n", o.Round+1, RoundNames[o.Round+1], d.Seconds())
		lastTime = time.Now()

		// Broadcast to the other parties
		err = o.SendMessageChannels(rangeSlice(1, n-1))
		require.NoError(err)
		o.Round++
	}

	// Wait for all go routines to finish
	wg.Wait()

	d = time.Since(lastTime)
	fmt.Printf("Round %d (%-12s) took %fs for the other parties\n", o.Round, RoundNames[o.Round], d.Seconds())
	lastTime = time.Now()

	// Check the results
	checkProtocolResults(
		t,
		pub,
		secret,
		rnd,
		outputCommitments,
		outputShares,
	)

	// Reset log level
	log.SetLevel(originalLogLevel)
}
