// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/cheekybits/genny

package curve25519

// This file is a template generating gen-matrix_generic.go

// PointMatrix is a matrix of curve25519 points
type PointMatrix struct {
	rows    int     // number of rows
	columns int     // number of columns
	entries []Point // row-major
}

func (m *PointMatrix) indexOf(i, j int) int {
	if i < 0 || i >= m.rows || j < 0 || j >= m.columns {
		panic("indexes out of bound")
	}
	return i*m.columns + j
}

// Rows returns the number of rows of the matrix
func (m *PointMatrix) Rows() int {
	return m.rows
}

// Columns returns the number of columns of the matrix
func (m *PointMatrix) Columns() int {
	return m.columns
}

// At returns the (i,j) coefficient
// panic is incorrect indexes
func (m *PointMatrix) At(i, j int) Point {
	return m.entries[m.indexOf(i, j)]
}

// Set sets the (i,j) coefficient to x
// panic is incorrect indexes
func (m *PointMatrix) Set(i, j int, x Point) {
	m.entries[m.indexOf(i, j)] = x
}

// NewPointMatrix creates a new Point matrix
func NewPointMatrix(rows, columns int) *PointMatrix {
	return &PointMatrix{
		rows:    rows,
		columns: columns,
		entries: make([]Point, rows*columns),
	}
}

func PointMatrixEqual(mat1, mat2 *PointMatrix) bool {
	if mat1.rows != mat2.rows || mat1.columns != mat2.columns {
		return false
	}
	for i := 0; i < mat1.rows*mat1.columns; i++ {
		if !PointEqual(mat1.entries[i], mat2.entries[i]) {
			return false
		}
	}
	return true
}

// This file is a template generating gen-matrix_generic.go

// ScalarMatrix is a matrix of curve25519 points
type ScalarMatrix struct {
	rows    int      // number of rows
	columns int      // number of columns
	entries []Scalar // row-major
}

func (m *ScalarMatrix) indexOf(i, j int) int {
	if i < 0 || i >= m.rows || j < 0 || j >= m.columns {
		panic("indexes out of bound")
	}
	return i*m.columns + j
}

// Rows returns the number of rows of the matrix
func (m *ScalarMatrix) Rows() int {
	return m.rows
}

// Columns returns the number of columns of the matrix
func (m *ScalarMatrix) Columns() int {
	return m.columns
}

// At returns the (i,j) coefficient
// panic is incorrect indexes
func (m *ScalarMatrix) At(i, j int) Scalar {
	return m.entries[m.indexOf(i, j)]
}

// Set sets the (i,j) coefficient to x
// panic is incorrect indexes
func (m *ScalarMatrix) Set(i, j int, x Scalar) {
	m.entries[m.indexOf(i, j)] = x
}

// NewScalarMatrix creates a new Scalar matrix
func NewScalarMatrix(rows, columns int) *ScalarMatrix {
	return &ScalarMatrix{
		rows:    rows,
		columns: columns,
		entries: make([]Scalar, rows*columns),
	}
}

func ScalarMatrixEqual(mat1, mat2 *ScalarMatrix) bool {
	if mat1.rows != mat2.rows || mat1.columns != mat2.columns {
		return false
	}
	for i := 0; i < mat1.rows*mat1.columns; i++ {
		if !ScalarEqual(mat1.entries[i], mat2.entries[i]) {
			return false
		}
	}
	return true
}
