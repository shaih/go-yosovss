package curve25519

// This file is a template generating gen-matrix_generic.go

import (
	"github.com/cheekybits/genny/generic"
)

//go:generate genny -in=$GOFILE -out=gen-$GOFILE gen "EntryType=Point,Scalar"

type EntryType generic.Type

// EntryTypeMatrix is a matrix of curve25519 points
type EntryTypeMatrix struct {
	rows    int         // number of rows
	columns int         // number of columns
	entries []EntryType // row-major
}

func (m *EntryTypeMatrix) indexOf(i, j int) int {
	if i < 0 || i >= m.rows || j < 0 || j >= m.columns {
		panic("indexes out of bound")
	}
	return i*m.columns + j
}

// Rows returns the number of rows of the matrix
func (m *EntryTypeMatrix) Rows() int {
	return m.rows
}

// Columns returns the number of columns of the matrix
func (m *EntryTypeMatrix) Columns() int {
	return m.columns
}

// At returns the (i,j) coefficient
// panic is incorrect indexes
func (m *EntryTypeMatrix) At(i, j int) *EntryType {
	return &m.entries[m.indexOf(i, j)]
}

// Set sets the (i,j) coefficient to x
// panic is incorrect indexes
func (m *EntryTypeMatrix) Set(i, j int, x *EntryType) {
	m.entries[m.indexOf(i, j)] = *x
}

// NewEntryTypeMatrix creates a new EntryType matrix
func NewEntryTypeMatrix(rows, columns int) *EntryTypeMatrix {
	return &EntryTypeMatrix{
		rows:    rows,
		columns: columns,
		entries: make([]EntryType, rows*columns),
	}
}

// EntryTypeMatrixFromEntries create a new EntrypeType matrix
// with the given entries in row-major order
// entries are *not* copied
// panic if length is inconsistent
func EntryTypeMatrixFromEntries(rows, columns int, entries []EntryType) *EntryTypeMatrix {
	if rows*columns != len(entries) {
		panic("incorrect size of entries")
	}
	return &EntryTypeMatrix{
		rows:    rows,
		columns: columns,
		entries: entries,
	}
}

func EntryTypeMatrixEqual(mat1, mat2 *EntryTypeMatrix) bool {
	if mat1.rows != mat2.rows || mat1.columns != mat2.columns {
		return false
	}
	for i := 0; i < mat1.rows*mat1.columns; i++ {
		if !EntryTypeEqual(&mat1.entries[i], &mat2.entries[i]) {
			return false
		}
	}
	return true
}
