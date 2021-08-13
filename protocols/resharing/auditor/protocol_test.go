package auditor

import (
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestResharingProtocol(t *testing.T) {
	// Test resharing protocol when everybody is honest
	var err error

	require := require.New(t)

	const (
		n          = 7                 // number of parties per committee
		numParties = n * numCommittees // total number of parties
		tt         = 2                 // threshold of malicious parties
	)

	pub, prvs, o, secret, rnd := setupResharingSeq(t, n, tt)

	// Output of all parties
	outputCommitments := make([][]pedersen.Commitment, numParties)
	outputShares := make([]*vss.Share, numParties)

	var wg sync.WaitGroup

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
	)
}

func TestResharingProtocolCheatingDealer(t *testing.T) {
	// Make the dealer 0 cheating so that it is disqualified

	var err error

	require := require.New(t)
	assert := assert.New(t)

	const (
		n          = 12                 // number of parties per committee
		numParties = n * numCommittees // total number of parties
		tt         = 2                 // threshold of malicious parties
	)

	pub, prvs, o, secret, rnd := setupResharingSeq(t, n, tt)

	// Output of all parties
	outputCommitments := make([][]pedersen.Commitment, numParties)
	outputShares := make([]*vss.Share, numParties)

	var wg sync.WaitGroup

	// Start protocol for all but dealer 0
	for party := 1; party < numParties; party++ {
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			outputShares[party], outputCommitments[party], err = StartCommitteeParty(pub, &prvs[party])
			require.NoError(err)
		}(party, &wg)
	}

	// Start cheating dealer 0
	{
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()

			// Dealing
			msg, err := PerformDealing(pub, &prvs[0])
			require.NoError(err)
			msg.ComS[0][0], err = curve25519.AddPoint(msg.ComS[0][0], msg.ComS[0][0]) // make the comS[0][0] incorrect
			prvs[0].BC.Send(msgpack.Encode(msg))
			prvs[0].BC.ReceiveRound()

			// Ver
			prvs[0].BC.Send([]byte{})
			prvs[0].BC.ReceiveRound()

			// Res
			prvs[0].BC.Send([]byte{})
			prvs[0].BC.ReceiveRound()

			// Wit
			prvs[0].BC.Send([]byte{})
			prvs[0].BC.ReceiveRound()

			// Aud
			prvs[0].BC.Send([]byte{})
			auditingMessages, err := ReceiveAuditingMessages(prvs[0].BC, pub.Committees.Aud)
			require.NoError(err)

			qualifiedDealers, _, err := ComputeQualifiedDealers(pub, auditingMessages)
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
	)
}
