package auditor

import (
	"crypto/rand"
	"math/big"
)

// AuditingMessage is the message witness committee members send during witness round
type AuditingMessage struct {
	_struct          struct{} `codec:",omitempty,omitemptyarray"`
	QualifiedDealers []bool   `codec:"Q"` // QualifiedDealers[i] = true iff the dealer is qualified
}

type FullWitness struct {
	Seed     [SeedLength]byte
	WitIndex int // index of the witness committee member with the given Seed, WitIndex = 0,...,n-1
}

// CryptoRandInt return a random integer between 0 and max-1
func CryptoRandInt(max int) (int, error) {
	// https://stackoverflow.com/a/26153749
	bg := big.NewInt(int64(max))

	// get big.Int between 0 and bg-1
	n, err := rand.Int(rand.Reader, bg)
	if err != nil {
		return 0, err
	}

	return int(n.Int64()), nil
}

func PerformAuditing(
	pub *PublicInput,
	dealingMessages []DealingMessage, witnessMessages []WitnessMessage,
) (
	*AuditingMessage, error,
) {

	invalidWit := make(map[int]struct{}) // set of invalid wit committee member
	qualifiedDealers := make([]bool, pub.N)

	for i := 0; i < pub.N; i++ {
		witnesses := make([]FullWitness, 0, pub.N) // list of witnesses
		nbWitnesses := 0                           // number of actual witnesses
		// since we cannot shrink the witnesses slice easily
		// what we do is moving the used witnesses to the end
		// and decrementing nbWitnesses
		// this way to pick a random witness, we just need to pick
		// an index between 0 and nbWitnesses - 1
		falseWitnesses := 0 // number of false witnesses detected

		// Get list of witnesses for non-invalidated wit committee members
		for l := 0; l < pub.N; l++ {
			if _, ok := invalidWit[l]; ok {
				// ignore invalid wit committee members
				continue
			}
			if witnessMessages[l].WitnessSeeds[i] != nil {
				witnesses = append(witnesses, FullWitness{
					Seed:     *witnessMessages[l].WitnessSeeds[i],
					WitIndex: l,
				})
				nbWitnesses++
			}
		}

		for {
			if nbWitnesses > pub.T-len(invalidWit) {
				// dealer i is disqualified
				break
			}

			if nbWitnesses < pub.AuditMinWitInvalidDealer || falseWitnesses >= pub.AuditMaxFalseWitDealer {
				// dealer i is qualified
				qualifiedDealers[i] = true

				// invalidate all wit committee members that provided witnesses inside
				for widx := 0; widx < nbWitnesses; widx++ {
					invalidWit[witnesses[widx].WitIndex] = struct{}{}
				}

				break
			}

			// Pick a random witness
			widx, err := CryptoRandInt(nbWitnesses)
			if err != nil {
				return nil, err
			}

			w := witnesses[widx]

			// Move the last witness at widx place so that
			// all the witnesses are between index 0 and nbWitnesses-2
			witnesses[widx] = witnesses[nbWitnesses-1]
			nbWitnesses--

			// check if valid
			valid, err := CheckDealerCommitmentsWithSeed(
				&pub.VSSParams,
				w.Seed,
				&pub.Commitments[i+1],
				dealingMessages[i].ComS,
			)
			if err != nil {
				return nil, err
			}

			if valid {
				// Passes the test, so invalid witness

				// mark the witness as invalid
				falseWitnesses++

				// invalidate the dealer
				invalidWit[w.WitIndex] = struct{}{}
			} else {
				// Does not pass the test, so valid witness
				// disqualify the dealer
				break
			}
		}
	}

	return &AuditingMessage{
		QualifiedDealers: qualifiedDealers,
	}, nil
}
