package auditor

import (
	"github.com/shaih/go-yosovss/communication/fake"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestResharingProtocol(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	const (
		numRounds  = 5     // number of rounds of messaging required for the protocol
		numParties = 3 * 6 // total number of parties
		n          = 3     // number of parties per committee
		tt         = 1     // threshold of malicious parties
	)

	// Create the orchestrator
	o := fake.NewOrchestrator()
	var channels []fake.PartyBroadcastChannel

	// Form initial committees, which are comprised of the ids of the parties that are participating in them
	committees := Committees{
		Hold: []int{0, 1, 2},
		Ver:  []int{3, 4, 5},
		Res:  []int{6, 7, 8},
		Wit:  []int{9, 10, 11},
		Aud:  []int{12, 13, 14},
		Next: []int{15, 16, 17},
	}

	// Generate parameters and keys
	encPKs, encSKs := curve25519.SetupKeys(numParties)
	sigPKs, sigSKs := curve25519.SetupSignKeys(numParties)
	vssParams, err := vss.NewVSSParams(
		pedersen.GenerateParams(),
		n,
		tt,
	)
	require.Nil(err)

	// Generate a Pedersen share of a secret
	secret := curve25519.RandomScalar() // secret s
	rnd := curve25519.RandomScalar()    // randomness r
	shares, commitments, err := vss.FixedRShare(vssParams, secret, rnd)

	// Public input
	pub := PublicInput{
		EncPKs:      encPKs,
		SigPKs:      sigPKs,
		VSSParams:   *vssParams,
		T:           tt,
		N:           n,
		Committees:  committees,
		Commitments: commitments,
	}

	// Initialize channels and connect with orchestrator
	for party := 0; party < numParties; party++ {
		channels = append(channels, fake.NewPartyBroadcastChannel(party))
		o.AddChannel(channels[party])
	}

	var wg sync.WaitGroup

	// Generate shares array: allPartiesShares[party] is nil if party not in holding/dealer committee
	// assume that holding committee is 0,...,n-1
	allPartiesShares := make([]*vss.Share, numParties)
	for i := 0; i < n; i++ {
		allPartiesShares[i] = &shares[i]
	}

	// Output of all parties
	outputCommitments := make([][]pedersen.Commitment, numParties)
	outputShares := make([]*vss.Share, numParties)

	// Start protocol
	for party := 0; party < numParties; party++ {
		wg.Add(1)
		go func(party int, wg *sync.WaitGroup) {
			defer wg.Done()
			prv := PrivateInput{
				BC:    channels[party],
				EncSK: encSKs[party],
				SigSK: sigSKs[party],
				Share: allPartiesShares[party],
				Id:    party,
			}
			outputShares[party], outputCommitments[party], err = StartCommitteeParty(&pub, &prv)
			require.Nil(err)
		}(party, &wg)
	}

	// Simulate the protocol for a fixed number of rounds
	// Naively switches rounds whenever every party has sent a message
	for o.Round < numRounds {
		err := o.ReceiveMessages()
		require.Nil(err)
		err = o.Broadcast()
		require.Nil(err)
		o.Round++
	}

	wg.Wait()

	// Check output commitments are all the same
	nextCommitments := outputCommitments[0]
	for party := 0; party < numParties; party++ {
		assert.Equalf(nextCommitments, outputCommitments[party], "all output commitments must be the same")
	}

	// Check nextCommitments[0] is commitments[0]
	assert.True(curve25519.PointEqual(nextCommitments[0], commitments[0]),
		"next commitment of secret should be the same as original one")

	// Check that original commitments are still valid
	valid, err := vss.VerifyCommitments(vssParams, commitments)
	require.Nil(err)
	assert.True(valid, "original commitments must be valid")

	// Check that next commitments are still valid
	valid, err = vss.VerifyCommitments(vssParams, nextCommitments)
	require.Nil(err)
	assert.True(valid, "next commitments must be valid")

	// Check only next committee members, aka numParties-n, ... numParties-1
	// have non-empty shares and extract the n above shares
	nextShares := make([]vss.Share, n)
	for party := 0; party < numParties-n; party++ {
		assert.Nil(outputShares[party], "non next-holder committee must output nil shares")
	}
	for party := numParties - n; party < numParties; party++ {
		assert.NotNil(outputShares[party])
		nextShares[party-(numParties-n)] = *outputShares[party]
	}

	// Check that all nextShares are valid
	for j := 0; j < n; j++ {
		vss.VerifyShare(vssParams, &nextShares[j], nextCommitments)
	}

	// Check the reconstructed secret is valid
	reconsSecret, reconsRnd, err := vss.ReconstructWithR(vssParams, nextShares, nextCommitments)
	require.Nil(err)
	assert.Equal(&secret, reconsSecret)
	assert.Equal(&rnd, reconsRnd)

	// Check that the new commitment to the secret is the expected one
	valid, err = pedersen.VerifyCommitment(vssParams.PedersenParams, &commitments[0], reconsSecret, reconsRnd)
	require.Nil(err)
	assert.True(valid)
}
