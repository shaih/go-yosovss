package curve25519

// #cgo CFLAGS: -Wall -std=c99
// #cgo LDFLAGS: -lsodium
// #include <stdint.h>
// #include "sodium.h"
import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"
)

func init() {
	if C.sodium_init() < 0 {
		log.Fatal("failed to initialize libsodium")
	}

	// Check sizes of structs
	_ = [C.crypto_core_ed25519_BYTES]byte(Point{})
	_ = [C.crypto_core_ed25519_SCALARBYTES]byte(Scalar{})
}

// Point is a group element on the ed25519 elliptic curve
type Point [32]byte

// Scalar is a non-negative integer
type Scalar [32]byte

// PointInfinity is the point at infinity
var PointInfinity Point = Point([32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0})

// ScalarZero is the scalar element 0
var ScalarZero Scalar = Scalar([32]byte{})

// ScalarOne is the scalar element 1
var ScalarOne Scalar = Scalar([32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0})

// IsValidPoint returns true if a point is on the ed25519 curve, non-zero,
// on the main subgroup, and of small order
// WARNING: VERY SLOW OPERATIONS: all other operations in this fail anyway if the point is not on the curve
//          but the point may not be on the correct order (which in general is not an issue)
func IsValidPoint(p *Point) bool {
	result := C.crypto_core_ed25519_is_valid_point((*C.uchar)(&p[0]))
	return result == 1
}

// PointEqual returns true if two points are equal
func PointEqual(p, q *Point) bool {
	return *p == *q
	// return C.sodium_memcmp(unsafe.Pointer(&p[0]), unsafe.Pointer(&q[0]), 32) == 0 // we don't do constant time
}

func PointFromHash(hashValue [64]byte) (*Point, error) {
	p := Point{}
	if C.crypto_core_ed25519_from_hash((*C.uchar)(&p[0]), (*C.uchar)(&hashValue[0])) != 0 {
		return nil, fmt.Errorf("error while hashing to curve")
	}
	return &p, nil
}

// ScalarEqual returns true if two scalars are equal
func ScalarEqual(x, y *Scalar) bool {
	return *x == *y
	// return C.sodium_memcmp(unsafe.Pointer(&x[0]), unsafe.Pointer(&y[0]), 32) == 0
}

// RandomPoint returns a random group element
func RandomPoint() *Point {
	var p Point

	C.crypto_core_ed25519_random((*C.uchar)(&p[0]))
	return &p
}

// GetScalar returns a scalar representation of an unsigned 64-bit integer
func GetScalar(x uint64) *Scalar {
	var s Scalar
	GetScalarC(&s, x)
	return &s
}

// GetScalarC is the same as GetScalar but with the return value as a first pointer
func GetScalarC(out *Scalar, x uint64) {
	binary.LittleEndian.PutUint64(out[:], x)
}

// RandomScalar returns a random scalar value in the range [0, L), where L is the order
// of the main subgroup
func RandomScalar() *Scalar {
	var r Scalar

	C.crypto_core_ed25519_scalar_random((*C.uchar)(&r[0]))
	return &r
}

// Just used for benchmarking
func sodium32RandomBytes() *[32]byte {
	var r [32]byte

	C.randombytes_buf(unsafe.Pointer(&r[0]), 32)
	return &r
}

// AddPoint computes the sum of two elliptic curve points
func AddPoint(p, q *Point) (*Point, error) {
	var r Point

	result := C.crypto_core_ed25519_add((*C.uchar)(&r[0]), (*C.uchar)(&p[0]), (*C.uchar)(&q[0]))
	if result != 0 {
		return nil, fmt.Errorf("failed to perform point addition: %d", result)
	}
	return &r, nil
}

// SubPoint computes the difference between two elliptic curve points
func SubPoint(p, q *Point) (*Point, error) {
	var r Point

	result := C.crypto_core_ed25519_sub((*C.uchar)(&r[0]), (*C.uchar)(&p[0]), (*C.uchar)(&q[0]))
	if result != 0 {
		return nil, fmt.Errorf("failed to perform point subtraction: %d", result)
	}
	return &r, nil
}

// InvertScalar computes the multiplicative inverse of a scalar mod L, where L is the order
// of the main subgroup
func InvertScalar(s *Scalar) (*Scalar, error) {
	var r Scalar

	result := C.crypto_core_ed25519_scalar_invert((*C.uchar)(&r[0]), (*C.uchar)(&s[0]))
	if result != 0 {
		return nil, fmt.Errorf("failed to perform scalar inversion: %d", result)
	}
	return &r, nil
}

// NegateScalar computes the additive inverse of a scalar mod L, where L is the order
// of the main subgroup
func NegateScalar(s *Scalar) *Scalar {
	var r Scalar

	C.crypto_core_ed25519_scalar_negate((*C.uchar)(&r[0]), (*C.uchar)(&s[0]))
	return &r
}

// AddScalar computes the sum of two scalars mod L
func AddScalar(x, y *Scalar) *Scalar {
	var z Scalar

	C.crypto_core_ed25519_scalar_add((*C.uchar)(&z[0]), (*C.uchar)(&x[0]), (*C.uchar)(&y[0]))
	return &z
}

// SubScalar computes the difference of two scalars mod L
func SubScalar(x, y *Scalar) *Scalar {
	var z Scalar

	C.crypto_core_ed25519_scalar_sub((*C.uchar)(&z[0]), (*C.uchar)(&x[0]), (*C.uchar)(&y[0]))
	return &z
}

// MultScalar computes the product of two scalars mod L
func MultScalar(x, y *Scalar) *Scalar {
	var z Scalar

	C.crypto_core_ed25519_scalar_mul((*C.uchar)(&z[0]), (*C.uchar)(&x[0]), (*C.uchar)(&y[0]))
	return &z
}

// multBaseGPointScalar computes the product of a scalar with the base point G
// not used as slowed than MultBaseGPointScalar
func multBaseGPointScalar2(n *Scalar) (*Point, error) {
	var r Point

	// High-level libsodium forbids result to be 0
	if *n == ScalarZero {
		r = PointInfinity
		return &r, nil
	}
	result := C.crypto_scalarmult_ed25519_base_noclamp((*C.uchar)(&r[0]), (*C.uchar)(&n[0]))
	if result != 0 {
		return nil, fmt.Errorf("failed to perform scalar multiplication: %d", result)
	}
	return &r, nil
}

// AddPointsNaive sums the points given as input
func AddPointsNaive(pointsToSum []Point) (*Point, error) {
	var err error
	r := &Point{}
	*r = PointInfinity
	for _, p := range pointsToSum {
		r, err = AddPoint(r, &p)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}
