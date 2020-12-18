package curve25519

import (
	"testing"
)

func TestIsValidPoint(t *testing.T) {
	p := RandomPoint()
	if !IsValidPoint(p) {
		t.Errorf("random point not valid")
	}
}

func TestAddPoint(t *testing.T) {
	p := RandomPoint()
	q := RandomPoint()
	r = AddPoint(p, q)

	if !ed25519Verify(pk, []byte{}, sig) {
		t.Errorf("sig of an empty message failed to verify")
	}
}
func TestEd25519Sub(t *testing.T) {

}

func TestEd25519Add(t *testing.T) {

}

func TestEd25519Add(t *testing.T) {

}
