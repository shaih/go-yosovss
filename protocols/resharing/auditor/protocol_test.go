package auditor

import (
	"sync"
	"testing"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/shaih/go-yosovss/primitives/shamir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResharingProtocol(t *testing.T) {
	// Test resharing protocol when everybody is honest
	var err error

	require := require.New(t)

	const (
		n          = 3                 // number of parties per committee
		numParties = n * numCommittees // total number of parties
		tt         = 1                 // threshold of malicious parties
	)

	pub, prvs, o, secret, rnd := setupResharingSeq(t, n, tt)

	// Output of all parties
	outputCommitments := make([][]feldman.GCommitment, numParties)
	outputShares := make([]*shamir.Share, numParties)

	var wg sync.WaitGroup

	// Start protocol
	for party := 0; party < numParties; party++ {
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err =
				StartCommitteeParty(pub, &prvs[party], &PartyDebugParams{})
			require.NoError(err)
		}(party, &wg)
	}

	// Simulate the protocol for a fixed number of rounds
	// Naively switches rounds whenever every party has sent a message
	for o.Round < numRounds {
		err := o.ReceiveMessages()
		require.NoError(err)
		err = o.Broadcast()
		require.NoError(err)
		o.Round++
	}

	// Wait for all go routines to finish
	wg.Wait()

	// Check the results
	checkProtocolResults(
		t,
		pub,
		secret,
		rnd,
		outputCommitments,
		outputShares,
		false,
	)
}

func TestResharingProtocolDealerInvalidComS(t *testing.T) {
	// Make the dealer 0 cheating so that it is disqualified
	// comS is made incorrect

	var err error

	require := require.New(t)
	assert := assert.New(t)

	const (
		n          = 12                // number of parties per committee
		numParties = n * numCommittees // total number of parties
		tt         = 2                 // threshold of malicious parties
	)

	pub, prvs, o, secret, rnd := setupResharingSeq(t, n, tt)

	// Output of all parties
	outputCommitments := make([][]feldman.GCommitment, numParties)
	outputShares := make([]*shamir.Share, numParties)

	var wg sync.WaitGroup

	// Start protocol for all but dealer 0
	for party := 1; party < numParties; party++ {
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err =
				StartCommitteeParty(pub, &prvs[party], &PartyDebugParams{})
			require.NoError(err)
		}(party, &wg)
	}

	// Start cheating dealer 0
	{
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()

			// Dealing
			msg, err := PerformDealing(pub, &prvs[0], &PartyDebugParams{})
			require.NoError(err)
			c, err := curve25519.AddPointXY(&msg.ComC[0], &msg.ComC[0]) // make the comC[0] incorrect
			require.NoError(err)
			msg.ComC[0] = *c
			prvs[0].BC.Send(msgpack.Encode(msg))
			prvs[0].BC.ReceiveRound()

			// Ver
			prvs[0].BC.Send([]byte{})
			prvs[0].BC.ReceiveRound()

			// Res
			prvs[0].BC.Send([]byte{})
			prvs[0].BC.ReceiveRound()

			// TODO CURRENTLY FAILS BECAUSE NO LINEAR TEST DONE
			qualifiedDealers, _, err := ComputeQualifiedDealers(pub, map[int]bool{})
			require.NoError(err)

			// Check qualified dealers are [1,...,t+1]
			assert.Equal(rangeSlice(1, pub.T+1), qualifiedDealers)
		}(&wg)
	}

	// Simulate the protocol for a fixed number of rounds
	// Naively switches rounds whenever every party has sent a message
	for o.Round < numRounds {
		err := o.ReceiveMessages()
		require.NoError(err)
		err = o.Broadcast()
		require.NoError(err)
		o.Round++
	}

	// Wait for all go routines to finish
	wg.Wait()

	// Check the results
	checkProtocolResults(
		t,
		pub,
		secret,
		rnd,
		outputCommitments[1:], // ignore dealer 0
		outputShares[1:],      // ignore dealer 0
		false,
	)
}

func TestResharingProtocolVerifiedComplain(t *testing.T) {
	// Make the verification member j=0 cheating and complaining about dealer 0
	// so that future broadcast needs to be used
	// Other parties are restricted to minimal work so party 0 can work properly
	// This is to allow testing on a single compuer

	var err error

	require := require.New(t)
	assert := assert.New(t)

	const (
		n          = 12                // number of parties per committee
		numParties = n * numCommittees // total number of parties
		tt         = 2                 // threshold of malicious parties
	)

	pub, prvs, o, secret, rnd := setupResharingSeq(t, n, tt)

	// Output of all parties
	outputCommitments := make([][]feldman.GCommitment, numParties)
	outputShares := make([]*shamir.Share, numParties)

	var wg sync.WaitGroup

	// Start protocol for all but dealer 0
	for party := 0; party < numParties; party++ {
		if party == n {
			// this is verification member j=0
			continue
		}
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err =
				StartCommitteeParty(pub, &prvs[party], &PartyDebugParams{})
			require.NoError(err)
		}(party, &wg)
	}

	// Start cheating dealer 0
	{
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()

			prv := prvs[n]

			// Dealing
			prv.BC.Send([]byte{})
			dealingMessages, err := ReceiveDealingMessages(prv.BC, pub.Committees.Hold)
			require.NoError(err)

			// Ver
			complaints := make([]bool, n)
			complaints[0] = true
			prv.BC.Send(msgpack.Encode(VerificationMessage{
				Complaints: complaints,
				EncShares:  nil,
			}))
			verificationMessages, err := ReceiveVerificationMessages(prv.BC, pub.Committees.Ver)
			require.NoError(err)

			// Res
			prv.BC.Send([]byte{})
			resolutionMessages, err := ReceiveResolutionMessages(prv.BC, pub.Committees.Res)
			require.NoError(err)

			_, disqualifiedDealers, err := ResolveComplaints(
				pub,
				dealingMessages,
				verificationMessages,
				resolutionMessages,
				&PartyDebugParams{},
			)
			require.NoError(err)
			qualifiedDealers, _, err := ComputeQualifiedDealers(pub, disqualifiedDealers)
			require.NoError(err)

			// Check qualified dealers are [0,...,t]
			assert.Equal(rangeSlice(0, pub.T+1), qualifiedDealers)
		}(&wg)
	}

	// Simulate the protocol for a fixed number of rounds
	// Naively switches rounds whenever every party has sent a message
	for o.Round < numRounds {
		err := o.ReceiveMessages()
		require.NoError(err)
		err = o.Broadcast()
		require.NoError(err)
		o.Round++
	}

	// Wait for all go routines to finish
	wg.Wait()

	// fix committee verification n:
	outputCommitments[n] = outputCommitments[0]
	outputShares[n] = outputShares[0]

	// Check the results
	checkProtocolResults(
		t,
		pub,
		secret,
		rnd,
		outputCommitments,
		outputShares,
		false,
	)
}
