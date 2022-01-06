package feldman

import "C"
import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/shaih/go-yosovss/primitives/curve25519"
)

// VC is a Feldman vector commitment
// Commitment of (x_0,...,x_n) is sum_i x_i G_i
// Note there are n+1 bases for consistency with other parts of the protocol
type VC = curve25519.PointXY

type VCParams struct {
	Bases []curve25519.PointXY // Bases G_0, ..., G_N used for VC, none of them are G/H
	N     int
}

// GenerateVCParams generates params for vector commitments
// Everytime it is called on the same n, it returns the same values
// Callers should not assume anything about calls with different n
// Current implementation uses the same G_0, G_1, ... for the longest prefix
// but this may change
// The only guarantee is that the G_i are distinct from G and H the two bases in curve25519
func GenerateVCParams(n int) (*VCParams, error) {
	if n <= 0 {
		return nil, fmt.Errorf("n needs to be > 0")
	}

	vcp := VCParams{
		N:     n,
		Bases: make([]curve25519.PointXY, n+1),
	}

	// Generates Bases[i] as Elligator(SHA512("... xxxx")) where xxxx is the 4-byte big-endian representation of i
	// WARNING TODO: Check it is ok to do it this way!!!
	h := sha512.New()
	hIn := []byte("vector commitment xxxx") // hash input, xxxx replaced by 4 byte of the index i
	for i := 0; i <= n; i++ {
		// Generate hIn
		binary.BigEndian.PutUint32(hIn[len(hIn)-4:], uint32(i))

		// Hash it into hOut64
		h.Reset()
		h.Write(hIn)
		hOut := h.Sum(nil)
		if len(hOut) != 64 {
			panic(fmt.Errorf("incorrect length output, expected 64 but got %d", len(hOut)))
		}
		hOut64 := [64]byte{}
		copy(hOut64[:], hOut)

		// Hash hOut64 to the curve
		p, err := curve25519.PointFromHash(hOut64)
		if err != nil {
			return nil, fmt.Errorf("error while generating G_%d: %w", i, err)
		}
		pxy, err := curve25519.PointToPointXY(p)
		if err != nil {
			return nil, fmt.Errorf("error while generating G_%d: %w", i, err)
		}
		vcp.Bases[i] = *pxy
	}

	return &vcp, nil
}
