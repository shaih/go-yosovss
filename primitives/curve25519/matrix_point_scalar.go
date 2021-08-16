package curve25519

// PointMatrixScalarMatrixMul multiplies a point matrix by a scalar matrix
func PointMatrixScalarMatrixMul(mat1 *PointMatrix, mat2 *ScalarMatrix) (*PointMatrix, error) {
	var err error

	err = MatricesMulCompatible(mat1, mat2)
	if err != nil {
		return nil, err
	}

	res := NewPointMatrix(mat1.rows, mat2.columns)

	for i := 0; i < res.rows; i++ {
		for j := 0; j < res.columns; j++ {
			var x *Point
			sum := &Point{}
			*sum = PointInfinity
			for k := 0; k < mat1.columns; k++ {
				x, err = MultPointScalar(mat1.At(i, k), mat2.At(k, j))
				if err != nil {
					return nil, err
				}
				sum, err = AddPoint(sum, x)
				if err != nil {
					return nil, err
				}
			}
			res.Set(i, j, sum)
		}
	}

	return res, nil
}

// PointScalarMatrixMul multiplies a scalar matrix by a single point
func PointScalarMatrixMul(g *Point, mat *ScalarMatrix) (*PointMatrix, error) {
	res := NewPointMatrix(mat.rows, mat.columns)

	for i := 0; i < res.rows; i++ {
		for j := 0; j < res.columns; j++ {
			x, err := MultPointScalar(g, mat.At(i, j))
			if err != nil {
				return nil, err
			}
			res.Set(i, j, x)
		}
	}

	return res, nil
}
