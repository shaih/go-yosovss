package curve25519

import "C"
import (
	"fmt"
	"github.com/shaih/go-yosovss/primitives/curve25519/myref10"
)

// WARNING: Everything in this file (but IsOnCurve) does not verify the point is on the curve!
//          Be careful to always check the point is on the curve beforehand.
//          This is different from compressed representation

// PointXY represents an elliptic curve point in (x,y) affine representation
type PointXY [64]byte

// PointXYInfinity is the point at infinity
var PointXYInfinity = PointXY{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0}

var (
	// generated from base.py
	BaseXYG = PointXY{0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21, 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}
	BaseXYH = PointXY{0x00, 0x88, 0x1a, 0xda, 0x54, 0x70, 0x0f, 0x83, 0x04, 0xf3, 0xbb, 0xd1, 0x1a, 0x88, 0xb6, 0xda, 0x29, 0x98, 0x4c, 0x59, 0x49, 0x6e, 0xb3, 0x03, 0xd4, 0xd3, 0x72, 0xc2, 0x8d, 0xd6, 0x09, 0x63, 0xdd, 0x9e, 0x4f, 0x62, 0x21, 0xd1, 0xde, 0xcb, 0x4f, 0x1e, 0x7e, 0x2c, 0x6e, 0xc8, 0xc4, 0x96, 0xe6, 0x64, 0x58, 0x32, 0xdb, 0xf6, 0x61, 0x87, 0x2c, 0xc7, 0xbb, 0xf4, 0x60, 0xf5, 0x4a, 0x16}
)

// IsOnCurveXY returns true if a point is on the ed25519 curve
// It may still be 0, of small order, or of too larger order
func IsOnCurveXY(p *PointXY) bool {
	result := myref10.Crypto_core_ed25519_is_on_curve(&p[0])
	return result == 1
}

// PointXYEqual returns true if two points are equal
// Non-constant time!
func PointXYEqual(p, q *Point) bool {
	return *p == *q
}

// PointToPointXY converts a Point to a PointXY
// WARNING: Slow, not optimized
func PointToPointXY(p *Point) (*PointXY, error) {
	var pxy PointXY

	result := myref10.Crypto_ed25519_compressed_to_xy(&pxy[0], &p[0])
	if result != 0 {
		return nil, fmt.Errorf("error converting point to xy")
	}

	return &pxy, nil
}

// RandomPointXY returns a random group element
// WARNING: Slow, not optimized!
func RandomPointXY() *PointXY {
	pxy, err := PointToPointXY(RandomPoint())
	if err != nil {
		panic(err) // should never happen
	}
	return pxy
}

// AddPointXY computes the sum of two elliptic curve points
func AddPointXY(p, q *PointXY) (*PointXY, error) {
	var r PointXY

	result := myref10.Crypto_ed25519_add_xy(&r[0], &p[0], &q[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform point addition: %d", result)
	}
	return &r, nil
}

// SubPointXY computes the difference between two elliptic curve points
func SubPointXY(p, q *PointXY) (*PointXY, error) {
	var r PointXY

	result := myref10.Crypto_ed25519_sub_xy(&r[0], &p[0], &q[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform point subtraction: %d", result)
	}
	return &r, nil
}

// AddPointsXY sums the points given as input using a more customized algorithm
func AddPointsXY(pointsToSum []PointXY) (*PointXY, error) {
	r := PointXY{}

	if len(pointsToSum) == 0 {
		r = PointXYInfinity
		return &r, nil
	}

	// TODO WARNING: using pointsToSum[0][0] assumes that the slice is contiguous
	result := myref10.Crypto_ed25519_add_points_xy(&r[0], &pointsToSum[0][0], len(pointsToSum))
	if result != 0 {
		return nil, fmt.Errorf("failed to summing points: %d", result)
	}

	return &r, nil
}

// AddPointsXYCheckOnCurve sums the points given as input using a more customized algorithm
// AND check they are on the curve: if not, return nil with an error
func AddPointsXYCheckOnCurve(pointsToSum []PointXY) (*PointXY, error) {
	r := PointXY{}

	if len(pointsToSum) == 0 {
		r = PointXYInfinity
		return &r, nil
	}

	// TODO WARNING: using pointsToSum[0][0] assumes that the slice is contiguous
	result := myref10.Crypto_ed25519_add_points_check_on_curve_xy(&r[0], &pointsToSum[0][0], len(pointsToSum))
	if result != 0 {
		return nil, fmt.Errorf("failed to summing points: %d", result)
	}

	return &r, nil
}

// AddPointsXYNaive sums the points given as input naively (non-optimized - used only for benchmarking)
func AddPointsXYNaive(pointsToSum []PointXY) (*PointXY, error) {
	var err error
	r := &PointXY{}
	*r = PointXYInfinity
	for _, p := range pointsToSum {
		r, err = AddPointXY(r, &p)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// MultPointXYScalar computes the product of a scalar with a point
func MultPointXYScalar(p *PointXY, n *Scalar) (*PointXY, error) {
	var r PointXY

	// High-level libsodium forbids result to be 0
	if *n == ScalarZero || *p == PointXYInfinity {
		r = PointXYInfinity
		return &r, nil
	}

	result := myref10.Crypto_scalarmult_ed25519_xy(&r[0], &n[0], &p[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform scalar multiplication: %d", result)
	}
	return &r, nil
}

func MultBaseHPointXYScalar(n *Scalar) (*PointXY, error) {
	var r PointXY

	result := myref10.Crypto_scalarmult_ed25519_base_h_xy(&r[0], &n[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform scalar multiplication: %d", result)
	}
	return &r, nil
}

func MultBaseGPointXYScalar(n *Scalar) (*PointXY, error) {
	var r PointXY

	result := myref10.Crypto_scalarmult_ed25519_base_g_xy(&r[0], &n[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform scalar multiplication: %d", result)
	}
	return &r, nil
}

// DoubleMultBaseGHPointXYScalar return ng * BaseG + nh * BaseH
func DoubleMultBaseGHPointXYScalar(ng *Scalar, nh *Scalar) (*PointXY, error) {
	var r PointXY

	result := myref10.Crypto_double_scalarmult_ed25519_base_gh_xy(&r[0], &ng[0], &nh[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform double scalar multiplication: %d", result)
	}
	return &r, nil
}
