package pedersen

import (
	"log"
	"testing"

	"github.com/shaih/go-yosovss/curve25519"
	"github.com/stretchr/testify/assert"
)

func TestPedersenCommitment(t *testing.T) {
	m := Message(curve25519.RandomScalar())
	n := Message(curve25519.RandomScalar())
	s := Decommitment(curve25519.RandomScalar())

	c, r, err := GenerateCommitment(m)
	if err != nil {
		log.Fatal(err)
	}

	isValid, err := VerifyCommitment(c, m, r)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid, "Commitment is consistent")

	isValid, err = VerifyCommitment(c, n, r)
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isValid, "Verification fails for wrong message")

	isValid, err = VerifyCommitment(c, m, &s)
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isValid, "Verification fails for wrong decommitment")
}
