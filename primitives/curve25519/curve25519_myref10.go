package curve25519

import "C"
import (
	"crypto/rand"
	"fmt"
	"github.com/shaih/go-yosovss/primitives/curve25519/myref10"
	"io"
)

const (
	Chacha20KeyLength = 32
)

type Chacha20Key [Chacha20KeyLength]byte

var (
	// generated from base.py
	BaseG = Point{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}
	BaseH = Point{0xdd, 0x9e, 0x4f, 0x62, 0x21, 0xd1, 0xde, 0xcb, 0x4f, 0x1e, 0x7e, 0x2c, 0x6e, 0xc8, 0xc4, 0x96, 0xe6, 0x64, 0x58, 0x32, 0xdb, 0xf6, 0x61, 0x87, 0x2c, 0xc7, 0xbb, 0xf4, 0x60, 0xf5, 0x4a, 0x16}
)

func MultBaseHPointScalar(n *Scalar) (*Point, error) {
	var r Point

	result := myref10.Crypto_scalarmult_ed25519_base_h(&r[0], &n[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform scalar multiplication: %d", result)
	}
	return &r, nil
}

func MultBaseGPointScalar(n *Scalar) (*Point, error) {
	var r Point

	result := myref10.Crypto_scalarmult_ed25519_base_g(&r[0], &n[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform scalar multiplication: %d", result)
	}
	return &r, nil
}

// DoubleMultBaseGHPointScalar return ng * BaseG + nh * BaseH
func DoubleMultBaseGHPointScalar(ng *Scalar, nh *Scalar) (*Point, error) {
	var r Point

	result := myref10.Crypto_double_scalarmult_ed25519_base_gh(&r[0], &ng[0], &nh[0])
	if result != 0 {
		return nil, fmt.Errorf("failed to perform double scalar multiplication: %d", result)
	}
	return &r, nil
}

// AddPoints sums the points given as input using a more customized algorithm
func AddPoints(pointsToSum []Point) (*Point, error) {
	r := Point{}

	if len(pointsToSum) == 0 {
		r = PointInfinity
		return &r, nil
	}

	// TODO WARNING: using pointsToSum[0][0] assumes that the slice is contiguous
	result := myref10.Crypto_ed25519_add_points(&r[0], &pointsToSum[0][0], len(pointsToSum))
	if result != 0 {
		return nil, fmt.Errorf("failed to summing points: %d", result)
	}

	return &r, nil
}

// Evaluate evaluates the polynomial p at a point x using a customized algorithm
func (p *Polynomial) Evaluate(x *Scalar) *Scalar {
	r := Scalar{}
	p.EvaluateC(&r, x)
	return &r
}

// EvaluateC is like Evaluate but with a pointer to the return value as first argument
func (p *Polynomial) EvaluateC(out *Scalar, x *Scalar) {
	// TODO WARNING: using pointsToSum[0][0] assumes that the slice is contiguous
	myref10.Crypto_ed25519_polynomial_evaluation(&out[0], &p.Coefficients[0][0], len(p.Coefficients)-1, &x[0])
}

// RandomScalarChacha20C is a function that generates a random scalar
// using Chacha20 on the provided key and nonce
// It is usually much faster than RandomScalar
// Should never be called with the same key and nonce
func RandomScalarChacha20C(out *Scalar, key *Chacha20Key, nonce uint64) {
	myref10.Crypto_core_ed25519_scalar_random_chacha20(&out[0], &key[0], nonce)
}

func RandomChacha20Key() (k Chacha20Key, err error) {
	_, err = io.ReadFull(rand.Reader, k[:])
	if err != nil {
		return [32]byte{}, err
	}
	return
}
