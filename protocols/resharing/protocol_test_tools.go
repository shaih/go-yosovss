package resharing

import (
	"testing"

	"github.com/shaih/go-yosovss/communication/fake"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupResharingSeq setup the resharing protocol for the given number of committees party n, the given treshold t
// the number of parties is n * numCommittees: each committee has n different parties taken in order
func setupResharingSeq(
	t testing.TB,
	n int,
	tt int,
) (
	pub *PublicInput,
	prvs []PrivateInput,
	o fake.Orchestrator,
	secret *curve25519.Scalar,
	rnd *curve25519.Scalar,
) {
	return setupResharing(t, n, tt, n*numCommittees, seqCommittees(n))
}

// setupResharingSame setup the resharing protocol for the given number of committees party n, the given treshold t
// the number of parties is n: each committee has the same n parties in the same order
// used for benchmarking essentially
func setupResharingSame(
	t testing.TB,
	n int,
	tt int,
) (
	pub *PublicInput,
	prvs []PrivateInput,
	o fake.Orchestrator,
	secret *curve25519.Scalar,
	rnd *curve25519.Scalar,
) {
	return setupResharing(t, n, tt, n, sameCommittees(n))
}

// setupResharing setup the resharing protocol for the given number of committees party n, the given treshold t
// the number of parties numParties, the committees Committees
func setupResharing(
	t testing.TB,
	n int,
	tt int,
	numParties int,
	committees Committees,
) (
	pub *PublicInput,
	prvs []PrivateInput,
	o fake.Orchestrator,
	secret *curve25519.Scalar,
	rnd *curve25519.Scalar,
) {
	require := require.New(t)

	// Create the orchestrator
	o = fake.NewOrchestrator()
	var channels []fake.PartyBroadcastChannel

	// Generate parameters and keys
	vcParams, err := feldman.GenerateVCParams(2 * n)
	require.NoError(err)
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
		VCParams:    *vcParams,
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

	// Generate shares array: allPartiesShares[party] is nil if party not in holding/dealer committee
	allPartiesShares := make([]*vss.Share, numParties)
	for i, party := range committees.Hold {
		allPartiesShares[party] = &shares[i]
	}

	// Generate the private inputs
	prvs = make([]PrivateInput, numParties)
	for party := 0; party < numParties; party++ {
		prvs[party] = PrivateInput{
			BC:    channels[party],
			EncSK: encSKs[party],
			SigSK: sigSKs[party],
			Share: allPartiesShares[party],
			ID:    party,
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
	secret *curve25519.Scalar,
	rnd *curve25519.Scalar,
	outputCommitments [][]feldman.GCommitment,
	outputShares []*vss.Share,
	allowMissingShares bool, // allow for shares to be missing,
	// e.g., not all new holding committee parties are simulated
	// remaining shares must be shares of new holding parties 0,1,... in this order (but last ones may be missing)
) {
	//var err error

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
	assert.True(curve25519.PointXYEqual(&nextCommitments[0], &pub.Commitments[0]),
		"next commitment of secret should be the same as original one")

	// Check that original commitments are still valid
	valid, err := vss.VerifyCommitments(&pub.VSSParams, pub.Commitments)
	require.NoError(err)
	assert.True(valid, "original commitments must be valid")

	// Check that next commitments are still valid
	valid, err = vss.VerifyCommitments(&pub.VSSParams, nextCommitments)
	require.NoError(err)
	assert.True(valid, "next commitments must be valid")

	if !allowMissingShares {
		require.GreaterOrEqual(len(outputShares), pub.N)
	}

	// Check only next committee members, aka numParties-n, ... numParties-1
	// have non-empty shares and extract the n above shares
	firstActualShare := max(len(outputShares)-pub.N, 0)
	nextShares := make([]vss.Share, len(outputShares)-firstActualShare)
	for party := 0; party < len(outputShares)-pub.N; party++ {
		assert.Nil(outputShares[party], "non next-holder committee must output nil shares")
	}
	for party := firstActualShare; party < len(outputShares); party++ {
		require.NotNil(outputShares[party])
		require.GreaterOrEqual(party-firstActualShare, 0)
		nextShares[party-firstActualShare] = *outputShares[party]
	}

	if !allowMissingShares {
		require.Equal(len(nextShares), pub.N)
	}

	// Check that all nextShares are valid
	for j := 0; j < len(nextShares); j++ {
		valid, err := vss.VerifyShare(vssParams, &nextShares[j], nextCommitments)
		require.NoError(err)
		assert.True(valid)
	}

	if len(outputShares) > pub.T+1 {
		// Check the reconstructed secret is valid
		reconsSecret, reconsRnd, err := vss.ReconstructWithR(vssParams, nextShares, nextCommitments)
		require.NoError(err)
		assert.Equal(*secret, *reconsSecret)
		assert.Equal(*rnd, *reconsRnd)

		// Check that the new commitment to the secret is the expected one
		valid, err = pedersen.VerifyCommitment(vssParams.PedersenParams, &commitments[0], reconsSecret, reconsRnd)
		require.NoError(err)
		assert.True(valid)
	}

	if len(outputShares) >= pub.T+1 {
		// Check the reconstructed secret is valid
		reconsSecret, err := vss.Reconstruct(vssParams, nextShares[:pub.T+1], nextCommitments)
		require.NoError(err)
		assert.Equal(*secret, *reconsSecret)
	}
}

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}
