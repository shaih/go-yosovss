package vss

import (
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/vss/paritycpp"
)

// ComputeParityMatrix computes the parity-check matrix H
// such that a sharing sigma = (sigma_0,...,sigma_n)
// (where sigma_0 is the secrete)
// is valid iff sigma * H = 0
// WARNING: This is the transpose of the code in cpp-lwevss
//
// Matrix has size (n+1) x (n+1-t)
func ComputeParityMatrix(n, t int) (*curve25519.ScalarMatrix, error) {
	entries := make([]byte, 32*(n+1)*(n-t+1))

	paritycpp.ComputeParityMatrixBytes(entries, n, t)

	mat := curve25519.NewScalarMatrix(n+1, n-t+1)
	err := mat.Decode(entries)
	if err != nil {
		return nil, err
	}

	return mat, nil
}
