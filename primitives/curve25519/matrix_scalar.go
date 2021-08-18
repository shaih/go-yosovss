package curve25519

import (
	"fmt"
	"github.com/shaih/go-yosovss/primitives/curve25519/myref10"
)

// Encode encodes a Scalar matrix into a byte string of
// 32*rows*columns bytes. Scalars are encoded one-by-one
// row-major order. Each scalar is encoded in little endian
func (m *ScalarMatrix) Encode() []byte {
	res := make([]byte, 32*m.rows*m.columns)
	for i := 0; i < m.rows*m.columns; i++ {
		copy(res[32*i:32*(i+1)], m.entries[i][:])
	}
	return res
}

// Decode decodes a Scalar matrix from a byte string of
// 32*rows*columns bytes. See Encode
func (m *ScalarMatrix) Decode(b []byte) error {
	if len(b) != 32*m.rows*m.columns {
		return fmt.Errorf("bytes to decode do not have the expected length")
	}
	for i := 0; i < m.rows*m.columns; i++ {
		copy(m.entries[i][:], b[32*i:32*(i+1)])
	}
	return nil
}

func ScalarMatrixMulNaive(mat1 *ScalarMatrix, mat2 *ScalarMatrix) (*ScalarMatrix, error) {
	err := MatricesMulCompatible(mat1, mat2)
	if err != nil {
		return nil, err
	}

	res := NewScalarMatrix(mat1.rows, mat2.columns)

	for i := 0; i < res.rows; i++ {
		for j := 0; j < res.columns; j++ {
			for k := 0; k < mat1.columns; k++ {
				var x *Scalar
				x = MultScalar(mat1.At(i, k), mat2.At(k, j))
				x = AddScalar(res.At(i, j), x)
				res.Set(i, j, x)
			}
		}
	}

	return res, nil
}

// ScalarMatrixMul is much faster than ScalarMatrixMulNaive
func ScalarMatrixMul(mat1 *ScalarMatrix, mat2 *ScalarMatrix) (*ScalarMatrix, error) {
	err := MatricesMulCompatible(mat1, mat2)
	if err != nil {
		return nil, err
	}

	res := NewScalarMatrix(mat1.rows, mat2.columns)

	myref10.Crypto_core_ed25519_scalar_matrix_mul(
		&res.entries[0][0],
		&mat1.entries[0][0],
		&mat2.entries[0][0],
		mat1.rows,
		mat1.columns,
		mat2.columns,
	)

	return res, nil
}

func (m *ScalarMatrix) Random() error {
	key, err := RandomChacha20Key()
	if err != nil {
		return err
	}

	for i := 0; i < len(m.entries); i++ {
		RandomScalarChacha20C(&m.entries[i], &key, uint64(i))
	}

	return nil
}

func (m *ScalarMatrix) IsZero() bool {
	for i := 0; i < m.rows*m.columns; i++ {
		if !ScalarEqual(&ScalarZero, &m.entries[i]) {
			return false
		}
	}
	return true
}
