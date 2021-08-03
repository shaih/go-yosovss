package curve25519

import (
	"fmt"
)

type Matrix interface {
	Rows() int
	Columns() int
}

// MatricesMulCompatible returns non-nil value if m1 and m2
// are not compatible, i.e., cannot be multiplied
func MatricesMulCompatible(mat1, mat2 Matrix) error {
	if mat1.Columns() != mat2.Rows() {
		return fmt.Errorf(
			"incorrect size for multiplications: %d != %d",
			mat1.Columns(),
			mat2.Rows(),
		)
	}
	return nil
}

// EntryTypeEqual is here just to make the Go compiler happy
// for matrix_generic.go
func EntryTypeEqual(_, _ EntryType) bool {
	return false
}
