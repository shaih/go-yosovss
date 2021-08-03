package curve25519

import "testing"

// Test both scalar and point scalar multiplication
func TestMatrixMul(t *testing.T) {
	g := RandomPoint()

	mat1 := &ScalarMatrix{
		rows:    3,
		columns: 2,
		entries: []Scalar{
			GetScalar(2), GetScalar(3),
			GetScalar(4), GetScalar(5),
			GetScalar(10), GetScalar(20),
		},
	}
	mat1Point, err := PointScalarMatrixMul(g, mat1)
	if err != nil {
		t.Error(err)
	}

	mat2 := &ScalarMatrix{
		rows:    2,
		columns: 4,
		entries: []Scalar{
			GetScalar(20), GetScalar(31), GetScalar(41), GetScalar(51),
			GetScalar(10), GetScalar(20), GetScalar(13), GetScalar(14),
		},
	}

	expectedMul := &ScalarMatrix{
		rows:    3,
		columns: 4,
		entries: []Scalar{
			GetScalar(70), GetScalar(122), GetScalar(121), GetScalar(144),
			GetScalar(130), GetScalar(224), GetScalar(229), GetScalar(274),
			GetScalar(400), GetScalar(710), GetScalar(670), GetScalar(790),
		},
	}
	expectedMulPoint, err := PointScalarMatrixMul(g, expectedMul)
	if err != nil {
		t.Error(err)
	}

	actualMul, err := ScalarMatrixMul(mat1, mat2)
	if err != nil {
		t.Error(err)
	}
	if !ScalarMatrixEqual(expectedMul, actualMul) {
		t.Errorf("incorrect scalar x scalar multiplication result")
	}

	actualMulPoint, err := PointMatrixScalarMatrixMul(mat1Point, mat2)
	if err != nil {
		t.Error(err)
	}

	if !PointMatrixEqual(expectedMulPoint, actualMulPoint) {
		t.Errorf("incorrect point x scalar multiplication result")
	}
}

func TestEncodeDecode(t *testing.T) {
	mat := &ScalarMatrix{
		rows:    3,
		columns: 2,
		entries: []Scalar{
			GetScalar(2), GetScalar(3),
			GetScalar(4), GetScalar(5),
			GetScalar(10), GetScalar(20),
		},
	}

	enc := mat.Encode()

	dec := NewScalarMatrix(mat.rows, mat.columns)
	err := dec.Decode(enc)
	if err != nil {
		t.Error(err)
	}

	if !ScalarMatrixEqual(mat, dec) {
		t.Errorf("decoded matrix does not match original matrix")
	}
}
