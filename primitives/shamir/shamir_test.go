package shamir

import (
	"log"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/stretchr/testify/assert"
)

func TestShamirSecretSharing(t *testing.T) {
	m := Message(*curve25519.RandomScalar())

	shares, err := GenerateShares(m, 2, 4)
	if err != nil {
		log.Fatal(err)
	}

	reconstruct := make([]Share, 2)
	reconstruct[0] = shares[2]
	reconstruct[1] = shares[1]

	res, err := Reconstruct(reconstruct)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, m, *res, "Commitment is consistent")
}
