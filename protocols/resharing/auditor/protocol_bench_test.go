package auditor

import (
	"fmt"
	"github.com/shaih/go-yosovss/communication/fake"
	"github.com/shaih/go-yosovss/msgpack"
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
			outputShares[party], outputCommitments[party], err = StartCommitteeParty(pub, &prvs[party], &PartyDebugParams{})
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
		true,
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
		tt         = 10       // threshold of malicious parties
		n          = 2*tt + 1 // number of parties per committee
		numParties = n        // total number of parties
	)

	fmt.Printf("TestResharingProtocolBenchmarkParty0: n=%d, t=%d\n", n, tt)

	pub, prvs, o, secret, rnd := setupResharingSame(t, n, tt)

	// Output of party 0
	outputCommitments := make([][]pedersen.Commitment, 1)
	outputShares := make([]*vss.Share, 1)

	var wg sync.WaitGroup

	lastTime := time.Now()

	// Start protocol for party 0
	party0done := make(chan bool)
	{
		party := 0
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err = StartCommitteeParty(pub, &prvs[party], &PartyDebugParams{})
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
			_, _, err = StartCommitteeParty(
				pub,
				&prvs[party],
				&PartyDebugParams{
					SkipWitness:                 true,
					SkipRefreshing:              true,
					SkipVerificationVerifyShare: true,
				},
			)
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
		true,
	)

	// Reset log level
	log.SetLevel(originalLogLevel)
}

func TestResharingProtocolBenchmarkManualParty0(t *testing.T) {
	// Test resharing protocol when everybody is honest
	// with some benchmarking
	// This test makes sure party 0 is run first and benchmark it individually
	// to get a better timing for a single party
	// Compared to TestResharingProtocolBenchmarkParty0, it avoids significant
	// cost in msgpack decoding by doing it only once

	var err error

	// Disable logging for efficiency
	originalLogLevel := log.GetLevel()
	log.SetLevel(log.ErrorLevel)

	require := require.New(t)

	const (
		// DO NOT FORGET TO SET BACK TO tt=3 TO ALLOW normal testing to be fast enough
		tt                                     = 10       // threshold of malicious parties
		n                                      = 2*tt + 1 // number of parties per committee
		numParties                             = n        // total number of parties
		skipDealingFutureBroadcastOtherParties = true     // skip generating future broadcast for other parties
		// (if true: slightly cheating on timing, and definitely cheating on size)
		// necessary for large n (otherwise way too slow)
	)

	fmt.Printf("TestResharingProtocolBenchmarkManualParty0: n=%d, t=%d\n", n, tt)

	pub, prvs, o, secret, rnd := setupResharingSame(t, n, tt)

	// Output of party 0
	outputCommitments := make([][]pedersen.Commitment, 1)
	outputShares := make([]*vss.Share, 1)

	lastTime := time.Now()

	// Dealing
	// =======

	runManualRound(t, n, &o, &lastTime, prvs, func(prv *PrivateInput, party int) (interface{}, error) {
		if party == 0 {
			return PerformDealing(pub, prv, &PartyDebugParams{})
		} else {
			return PerformDealing(pub, prv, &PartyDebugParams{
				SkipDealingFutureBroadcast: skipDealingFutureBroadcastOtherParties})
		}
	})

	// Ver
	// ===

	// Remark we only decode dealing messages once here
	// that means we don't have any copy
	// The decoding time is counted in party 0 time which is fair
	dealingMessages, err := ReceiveDealingMessages(prvs[0].BC, pub.Committees.Hold)
	require.NoError(err)

	runManualRound(t, n, &o, &lastTime, prvs, func(prv *PrivateInput, party int) (interface{}, error) {
		return PerformVerification(pub, prv, party, dealingMessages, &PartyDebugParams{
			SkipVerificationVerifyShare: party != 0,
		})
	})

	// Res
	// ===

	verificationMessages, err := ReceiveVerificationMessages(prvs[0].BC, pub.Committees.Ver)
	require.NoError(err)

	runManualRound(t, n, &o, &lastTime, prvs, func(prv *PrivateInput, party int) (interface{}, error) {
		return PerformResolution(pub, prv, party, dealingMessages, verificationMessages)
	})

	// Wit
	// ===

	resolutionMessages, err := ReceiveResolutionMessages(prvs[0].BC, pub.Committees.Res)
	require.NoError(err)

	runManualRound(t, n, &o, &lastTime, prvs, func(prv *PrivateInput, party int) (interface{}, error) {
		if party == 0 {
			return PerformWitness(pub, dealingMessages)
		} else {
			// we skip witness for party non-zero
			return &WitnessMessage{
				WitnessSeeds: make([]*[SeedLength]byte, pub.N),
			}, nil
		}
	})

	// Aud
	// ===

	witnessMessages, err := ReceiveWitnessMessages(prvs[0].BC, pub.Committees.Wit)
	require.NoError(err)

	runManualRound(t, n, &o, &lastTime, prvs, func(prv *PrivateInput, party int) (interface{}, error) {
		return PerformAuditing(pub, dealingMessages, witnessMessages)
	})

	// Refreshing
	// ==========

	auditingMessages, err := ReceiveAuditingMessages(prvs[0].BC, pub.Committees.Aud)
	require.NoError(err)

	runManualRound(t, n, &o, &lastTime, prvs, func(prv *PrivateInput, party int) (interface{}, error) {
		if party == 0 {
			outputCommitments[0], outputShares[0], err = PerformRefresh(
				pub,
				prv,
				dealingMessages,
				verificationMessages,
				resolutionMessages,
				auditingMessages,
				party,
				&PartyDebugParams{SkipDealingFutureBroadcast: skipDealingFutureBroadcastOtherParties},
			)
			return struct{}{}, nil
		} else {
			// we skip witness for party non-zero
			return struct{}{}, nil
		}
	})

	// Check the results
	checkProtocolResults(
		t,
		pub,
		secret,
		rnd,
		outputCommitments,
		outputShares,
		true,
	)

	// Reset log level
	log.SetLevel(originalLogLevel)
}

type roundFunc func(prv *PrivateInput, party int) (interface{}, error)

func runManualRound(t *testing.T, n int, o *fake.Orchestrator, lastTime *time.Time, prvs []PrivateInput, f roundFunc) {
	require := require.New(t)

	// Party 0

	{
		party := 0
		prv := &prvs[party]
		msg, err := f(prv, party)
		require.NoError(err)
		prv.BC.Send(msgpack.Encode(msg))
	}

	d := time.Since(*lastTime)
	fmt.Printf("Round %d (%-12s) took %fs for party 0\n", o.Round, RoundNames[o.Round], d.Seconds())
	*lastTime = time.Now()

	// Other parties

	{
		var wg sync.WaitGroup
		for party := 1; party < n; party++ {
			wg.Add(1)
			go func(party int, wg *sync.WaitGroup) {
				defer wg.Done()
				prv := &prvs[party]
				msg, err := f(prv, party)
				require.NoError(err)
				prv.BC.Send(msgpack.Encode(msg))
			}(party, &wg)
		}
		wg.Wait()
	}

	nextManualRound(t, o, lastTime)
}

func nextManualRound(t *testing.T, o *fake.Orchestrator, lastTime *time.Time) {
	require := require.New(t)
	var err error

	err = o.ReceiveMessages()
	require.NoError(err)
	err = o.SendMessageChannels([]int{0}) // only send to party 0, the others don't need it
	require.NoError(err)

	d := time.Since(*lastTime)
	fmt.Printf("Round %d (%-12s) took %fs for the other parties\n", o.Round, RoundNames[o.Round], d.Seconds())
	*lastTime = time.Now()

	o.Round++
}

func BenchmarkPerformDealing(b *testing.B) {
	var err error

	// Disable logging for efficiency
	originalLogLevel := log.GetLevel()
	log.SetLevel(log.ErrorLevel)

	require := require.New(b)

	const (
		tt         = 64       // threshold of malicious parties
		n          = 2*tt + 1 // number of parties per committee
		numParties = n        // total number of parties
	)

	fmt.Printf("BenchmarkPerformDealing: n=%d, t=%d\n", n, tt)

	pub, prvs, _, _, _ := setupResharingSame(b, n, tt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = PerformDealing(pub, &prvs[0], &PartyDebugParams{})
		require.NoError(err)
	}

	// Reset log level
	log.SetLevel(originalLogLevel)
}
