package auditor

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
	"io"
)

const (
	SeedLength = 16 // = 128 bits, the length of seeds
)

// WitnessMessage is the message witness committee members send during witness round
type WitnessMessage struct {
	_struct      struct{}            `codec:",omitempty,omitemptyarray"`
	WitnessSeeds []*[SeedLength]byte `codec:"W"` // WitnessSeeds[i] = nil if dealer passed the test, or a witness seed otherwise
}

// SeedToBytes fills the array out with random bytes derived deterministically from the seed
// use HKDF with SHA256
// TODO: this is most likely not really optimal as AES counter would be faster
func SeedToBytes(seed [SeedLength]byte, out []byte) error {
	hash := sha256.New
	r := hkdf.Expand(hash, seed[:], nil)
	_, err := io.ReadFull(r, out)
	return err
}

// GetBit returns the i-th bit of a byte array
// panic if length incorrect
func GetBit(b []byte, i int) bool {
	return (b[i/8] & (1 << (i % 8))) != 0
}

// CheckDealerCommitmentsWithSeed checks if a dealer's commitments passes the test against the seed
// origCom is the original commitment of the dealer i (i.e., S_i = S_{i,0,0})
// comS is the array of commitments published by the dealer i
// (i.e., comS[j][k] = S_{i,j+1,k}, where j in {0,...,n-1} and k in {0,...,n}
// see DealingMessage
func CheckDealerCommitmentsWithSeed(
	vssParams *vss.Params, seed [SeedLength]byte,
	origCom *pedersen.Commitment, comS [][]pedersen.Commitment,
) (
	valid bool,
	err error,
) {
	n := vssParams.N

	comSprime := make([]pedersen.Commitment, n+1) // comSprime is the row vector
	// that is the product of the rows of commitments selected by the seed

	// Expand the seed
	r := make([]byte, (n+7)/8)
	err = SeedToBytes(seed, r)
	if err != nil {
		return false, fmt.Errorf("error converting seed to bytes: %w", err)
	}

	//// Set comSprime to 0
	//for k := 0; k < n+1; k++ {
	//	comSprime[k] = curve25519.PointInfinity
	//}

	for k := 0; k < n+1; k++ {
		pointsToSum := make([]curve25519.Point, 0, n+1)

		// First row is a bit different: it is origCom, comS[0][0], ..., comS[n-1][0]
		if GetBit(r, 0) {
			if k == 0{
				pointsToSum = append(pointsToSum, *origCom)
			} else {
				pointsToSum = append(pointsToSum, comS[k-1][0])
			}
		}

		// Other rows are normal
		for j := 0; j < n; j++ {
			if GetBit(r, j+1) { // row (j+1) is selected
				pointsToSum = append(pointsToSum, comS[j][k])
			}
		}

		// Sum all the selected points
		c, err := curve25519.AddPoints(pointsToSum)
		if err != nil {
			return false, fmt.Errorf("error while adding points for k=%d: %w", k, err)
		}
		comSprime[k] = *c
	}

	// Check comS' is ok
	return vss.VerifyCommitmentsRandomized(vssParams, comSprime)
}

// PerformWitness executes what a witness committee member does in the dealing round
// and returns the message it should broadcast
func PerformWitness(
	pub *PublicInput,
	dealingMessages []DealingMessage,
) (
	*WitnessMessage, error,
) {
	var err error

	myLog := log.WithFields(log.Fields{
		"committee": "verification",
	})

	witnessSeeds := make([]*[SeedLength]byte, pub.N)

	for i := 0; i < pub.N; i++ {
		// Pick a new seed
		witnessSeeds[i] = &[SeedLength]byte{}
		_, err = rand.Read(witnessSeeds[i][:])
		if err != nil {
			return nil, err
		}

		valid, err := CheckDealerCommitmentsWithSeed(
			&pub.VSSParams, *witnessSeeds[i], &pub.Commitments[i+1], dealingMessages[i].ComS,
		)
		if err != nil {
			return nil, err
		}

		if valid {
			witnessSeeds[i] = nil
		} else {
			myLog.Infof("commitment of dealer %d is incorrect", i)
		}
	}

	msg := WitnessMessage{
		WitnessSeeds: witnessSeeds,
	}

	return &msg, nil
}
