package oldvss

import (
	"log"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/stretchr/testify/assert"
)

func TestPedersenVSS(t *testing.T) {
	m := pedersen.Message(curve25519.RandomScalar())

	params := pedersen.GenerateParams()

	shares, verifications, err := VSSShare(params, m, 3, 4)
	if err != nil {
		log.Fatal(err)
	}

	isValid1, err := VSSVerify(params, shares[0], verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid1, "Verification is verifies valid share")

	isValid2, err := VSSVerify(params, shares[1], verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid2, "Verification is verifies valid share")

	isValid3, err := VSSVerify(params, shares[2], verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid3, "Verification is verifies valid share")

	reconstruction1, err := VSSReconstruct(params, shares, verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, m, *reconstruction1, "VSS is consistent")

	invalidShare := Share{
		Index:       1,
		IndexScalar: curve25519.ScalarOne,
		S:           curve25519.RandomScalar(),
		R:           curve25519.RandomScalar(),
	}
	modifiedShares := shares
	modifiedShares[0] = invalidShare

	reconstruction2, err := VSSReconstruct(params, modifiedShares, verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, m, *reconstruction2, "VSS with modified shares, above threshold")

	modifiedShares[2] = invalidShare

	_, err = VSSReconstruct(params, modifiedShares, verifications)
	assert.EqualError(t, err, "insufficient valid shares", "VSS fails below threshold valid shares")
}

func TestPedersenVSSFixedR(t *testing.T) {
	m := pedersen.Message(curve25519.RandomScalar())
	r := pedersen.Decommitment(curve25519.RandomScalar())

	params := pedersen.GenerateParams()

	shares, verifications, err := VSSShareFixedR(params, m, r, 3, 4)
	if err != nil {
		log.Fatal(err)
	}

	isValid1, err := VSSVerify(params, shares[0], verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid1, "Verification is verifies valid share")

	isValid2, err := VSSVerify(params, shares[1], verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid2, "Verification is verifies valid share")

	isValid3, err := VSSVerify(params, shares[2], verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid3, "Verification is verifies valid share")

	reconstruction1, err := VSSReconstruct(params, shares, verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, m, *reconstruction1, "VSS is consistent")

	invalidShare := Share{
		Index:       1,
		IndexScalar: curve25519.ScalarOne,
		S:           curve25519.RandomScalar(),
		R:           curve25519.RandomScalar(),
	}
	modifiedShares := shares
	modifiedShares[0] = invalidShare

	reconstruction2, err := VSSReconstruct(params, modifiedShares, verifications)
	if err != nil {
		log.Fatal(err)
	}
	assert.Equal(t, m, *reconstruction2, "VSS with modified shares, above threshold")

	modifiedShares[2] = invalidShare

	_, err = VSSReconstruct(params, modifiedShares, verifications)
	assert.EqualError(t, err, "insufficient valid shares", "VSS fails below threshold valid shares")
}