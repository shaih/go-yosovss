package auditor

import (
	"github.com/shaih/go-yosovss/communication/fake"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

// setupResharingSeq setup the resharing protocol for the given number of committees party n, the given treshold t
// the number of parties is n * numCommittees: each committee has n different parties taken in order
func setupResharingSeq(
	t *testing.T,
	n int,
	tt int,
) (
	pub *PublicInput,
	prvs []PrivateInput,
	o fake.Orchestrator,
	secret curve25519.Scalar,
	rnd curve25519.Scalar,
) {
	require := require.New(t)

	numParties := n * numCommittees

	// Create the orchestrator
	o = fake.NewOrchestrator()
	var channels []fake.PartyBroadcastChannel

	// Form initial committees, which are comprised of the ids of the parties that are participating in them
	committees := seqCommittees(n)

	// Generate parameters and keys
	encPKs, encSKs := curve25519.SetupKeys(numParties)
	sigPKs, sigSKs := curve25519.SetupSignKeys(numParties)
	vssParams, err := vss.NewVSSParams(
		pedersen.GenerateParams(),
		n,
		tt,
	)
	require.NoError(err)

	// Generate a Pedersen share of a secret
	secret = curve25519.RandomScalar() // secret s
	rnd = curve25519.RandomScalar()    // randomness r
	shares, commitments, err := vss.FixedRShare(vssParams, secret, rnd)
	require.NoError(err)

	// Public input
	pub = &PublicInput{
		EncPKs:                   encPKs,
		SigPKs:                   sigPKs,
		VSSParams:                *vssParams,
		T:                        tt,
		N:                        n,
		AuditMinWitInvalidDealer: 1,
		AuditMaxFalseWitDealer:   tt,
		Committees:               committees,
		Commitments:              commitments,
	}

	// Initialize channels and connect with orchestrator
	for party := 0; party < numParties; party++ {
		channels = append(channels, fake.NewPartyBroadcastChannel(party))
		o.AddChannel(channels[party])
	}

	// Generate shares array: allPartiesShares[party] is nil if party not in holding/dealer committee
	// assume that holding committee is 0,...,n-1
	allPartiesShares := make([]*vss.Share, numParties)
	for i := 0; i < n; i++ {
		allPartiesShares[i] = &shares[i]
	}

	// Generate the private inputs
	prvs = make([]PrivateInput, numParties)
	for party := 0; party < numParties; party++ {
		prvs[party] = PrivateInput{
			BC:    channels[party],
			EncSK: encSKs[party],
			SigSK: sigSKs[party],
			Share: allPartiesShares[party],
			Id:    party,
		}
	}

	return
}

// checkProtocolResults verify all the results of the protocols are as expected
// outputCommitments can be an array of any number of output commitments (at least one)
// outputCommitments[0]=...=outputcommitments[...] are the next commitments (error is printed if they're not all equal)
// The last n values of outputShares are the shares output by the new holding committee.
// The other values are checked to be nil
func checkProtocolResults(
	t *testing.T,
	pub *PublicInput,
	secret curve25519.Scalar,
	rnd curve25519.Scalar,
	outputCommitments [][]pedersen.Commitment,
	outputShares []*vss.Share,
) {
	var err error

	require := require.New(t)
	assert := assert.New(t)

	vssParams := &pub.VSSParams
	commitments := pub.Commitments

	// Check output commitments are all the same
	nextCommitments := outputCommitments[0]
	for party := 0; party < len(outputCommitments); party++ {
		assert.Equalf(nextCommitments, outputCommitments[party], "all output commitments must be the same")
	}

	// Check nextCommitments[0] is commitments[0]
	assert.True(curve25519.PointEqual(nextCommitments[0], commitments[0]),
		"next commitment of secret should be the same as original one")

	// Check that original commitments are still valid
	valid, err := vss.VerifyCommitments(vssParams, commitments)
	require.NoError(err)
	assert.True(valid, "original commitments must be valid")

	// Check that next commitments are still valid
	valid, err = vss.VerifyCommitments(vssParams, nextCommitments)
	require.NoError(err)
	assert.True(valid, "next commitments must be valid")

	// Check only next committee members, aka numParties-n, ... numParties-1
	// have non-empty shares and extract the n above shares
	nextShares := make([]vss.Share, pub.N)
	for party := 0; party < len(outputShares)-pub.N; party++ {
		assert.Nil(outputShares[party], "non next-holder committee must output nil shares")
	}
	for party := len(outputShares) - pub.N; party < len(outputShares); party++ {
		assert.NotNil(outputShares[party])
		nextShares[party-(len(outputShares)-pub.N)] = *outputShares[party]
	}

	// Check that all nextShares are valid
	for j := 0; j < pub.N; j++ {
		valid, err := vss.VerifyShare(vssParams, &nextShares[j], nextCommitments)
		require.NoError(err)
		assert.True(valid)
	}

	// Check the reconstructed secret is valid
	reconsSecret, reconsRnd, err := vss.ReconstructWithR(vssParams, nextShares, nextCommitments)
	require.NoError(err)
	assert.Equal(&secret, reconsSecret)
	assert.Equal(&rnd, reconsRnd)

	// Check that the new commitment to the secret is the expected one
	valid, err = pedersen.VerifyCommitment(vssParams.PedersenParams, &commitments[0], reconsSecret, reconsRnd)
	require.NoError(err)
	assert.True(valid)
}
