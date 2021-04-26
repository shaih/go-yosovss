package pedersen

import (
	"log"
	"testing"

	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/stretchr/testify/assert"
)

func TestPedersenCommitment(t *testing.T) {
	m := Message(curve25519.RandomScalar())
	n := Message(curve25519.RandomScalar())
	s := Decommitment(curve25519.RandomScalar())

	params := GenerateParams()

	c, r, err := GenerateCommitment(params, m)
	if err != nil {
		log.Fatal(err)
	}

	isValid, err := VerifyCommitment(params, c, m, r)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid, "Commitment is consistent")

	isValid, err = VerifyCommitment(params, c, n, r)
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isValid, "Verification fails for wrong message")

	isValid, err = VerifyCommitment(params, c, m, &s)
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isValid, "Verification fails for wrong decommitment")
}

func TestPedersenCommitmentFixedR(t *testing.T) {
	m := Message(curve25519.RandomScalar())
	n := Message(curve25519.RandomScalar())
	r := Decommitment(curve25519.RandomScalar())
	s := Decommitment(curve25519.RandomScalar())

	params := GenerateParams()

	c, err := GenerateCommitmentFixedR(params, m, r)
	if err != nil {
		log.Fatal(err)
	}

	isValid, err := VerifyCommitment(params, c, m, &r)
	if err != nil {
		log.Fatal(err)
	}
	assert.True(t, isValid, "Commitment is consistent")

	isValid, err = VerifyCommitment(params, c, n, &r)
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isValid, "Verification fails for wrong message")

	isValid, err = VerifyCommitment(params, c, m, &s)
	if err != nil {
		log.Fatal(err)
	}
	assert.False(t, isValid, "Verification fails for wrong decommitment")
}

func TestPedersenVSS(t *testing.T) {
	m := Message(curve25519.RandomScalar())

	params := GenerateParams()

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
	m := Message(curve25519.RandomScalar())
	r := Decommitment(curve25519.RandomScalar())

	params := GenerateParams()

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
