package auditor

import (
	"fmt"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

func TestGetBit(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		arr []byte
		i   int
		b   bool
	}{
		{[]byte{0x00}, 0, false},
		{[]byte{0x00}, 7, false},
		{[]byte{0x10}, 1, false},
		{[]byte{0x10}, 4, true},
		{[]byte{0x01, 0x02, 0x04, 0x08}, 0, true},
		{[]byte{0x01, 0x02, 0x04, 0x08}, 1, false},
		{[]byte{0x01, 0x02, 0x04, 0x08}, 8, false},
		{[]byte{0x01, 0x02, 0x04, 0x08}, 9, true},
		{[]byte{0x01, 0x02, 0x04, 0x08}, 27, true},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("arr=%v,i=%d", tc.arr, tc.i), func(t *testing.T) {
			assert.Equal(tc.b, GetBit(tc.arr, tc.i))
		})
	}
}

func TestSeedToBytes(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	seed1 := [SeedLength]byte{0x01}
	seed2 := [SeedLength]byte{0x02}

	r1 := make([]byte, 40)
	r2 := make([]byte, 40)

	err := SeedToBytes(seed1, r1)
	require.NoError(err)

	err = SeedToBytes(seed2, r2)
	require.NoError(err)

	assert.NotEqual(r1, r2, "randomness generated by two different seeds must be different")

	r1b := make([]byte, 40)
	err = SeedToBytes(seed1, r1b)
	require.NoError(err)

	assert.Equal(r1, r1b, "SeedToBytes must be deterministic")
}

func TestCheckDealerCommitmentsWithSeed(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	n := 11
	tt := 7
	vssParams, err := vss.NewVSSParams(pedersen.GenerateParams(), n, tt-1)
	require.NoError(err)

	s := curve25519.RandomScalar()
	r := curve25519.RandomScalar()
	origCom, err := pedersen.GenerateCommitmentFixedR(vssParams.PedersenParams, s, r)
	require.NoError(err)

	_, comS, err := GenerateDealerSharesCommitments(vssParams, s, r)

	seed := [SeedLength]byte{0x01, 0x02}
	valid, err := CheckDealerCommitmentsWithSeed(vssParams, seed, origCom, comS)
	require.NoError(err)
	assert.True(valid, "valid commitments should pass the test")

	// make the commitments incorrect
	c, err := curve25519.AddPointXY(&comS[2][3], &comS[2][3])
	require.NoError(err)
	comS[2][3] = *c

	// be sure that after 20 times we're sure to find an issue
	invalid := false
	for i := 0; i < 20; i++ {
		// generate a new random seed
		_, err = rand.Read(seed[:])
		require.NoError(err)

		// make the test
		valid, err = CheckDealerCommitmentsWithSeed(vssParams, seed, origCom, comS)
		require.NoError(err)

		if !valid {
			invalid = true
			break
		}
	}
	assert.True(invalid, "commitments should have been detected as invalid at least once over 20 tries")
}

func BenchmarkCheckDealerCommitmentsWithSeed(b *testing.B) {
	assert := assert.New(b)
	require := require.New(b)

	// Don't forget to switch back to a small n
	const (
		tt = 64
		n  = 2*tt + 1
	)

	fmt.Printf("BenchmarkCheckDealerCommitmentsWithSeed n=%d, t=%d\n", n, tt)

	vssParams, err := vss.NewVSSParams(pedersen.GenerateParams(), n, tt-1)
	require.NoError(err)

	s := curve25519.RandomScalar()
	r := curve25519.RandomScalar()
	origCom, err := pedersen.GenerateCommitmentFixedR(vssParams.PedersenParams, s, r)
	require.NoError(err)

	_, comS, err := GenerateDealerSharesCommitments(vssParams, s, r)

	seed := [SeedLength]byte{0x01, 0x02}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		valid, err := CheckDealerCommitmentsWithSeed(vssParams, seed, origCom, comS)
		require.NoError(err)
		assert.True(valid, "valid commitments should pass the test")
	}
}
