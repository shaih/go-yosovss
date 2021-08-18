package curve25519

// PointXYMatrixScalarMatrixMul multiplies a point matrix by a scalar matrix
func PointXYMatrixScalarMatrixMul(mat1 *PointXYMatrix, mat2 *ScalarMatrix) (*PointXYMatrix, error) {
	var err error

	err = MatricesMulCompatible(mat1, mat2)
	if err != nil {
		return nil, err
	}

	res := NewPointXYMatrix(mat1.rows, mat2.columns)

	for i := 0; i < res.rows; i++ {
		for j := 0; j < res.columns; j++ {
			var x *PointXY
			sum := &PointXY{}
			*sum = PointXYInfinity
			for k := 0; k < mat1.columns; k++ {
				x, err = MultPointXYScalar(mat1.At(i, k), mat2.At(k, j))
				if err != nil {
					return nil, err
				}
				sum, err = AddPointXY(sum, x)
				if err != nil {
					return nil, err
				}
			}
			res.Set(i, j, sum)
		}
	}

	return res, nil
}

// PointXYScalarMatrixMul multiplies a scalar matrix by a single point
func PointXYScalarMatrixMul(g *PointXY, mat *ScalarMatrix) (*PointXYMatrix, error) {
	res := NewPointXYMatrix(mat.rows, mat.columns)

	for i := 0; i < res.rows; i++ {
		for j := 0; j < res.columns; j++ {
			x, err := MultPointXYScalar(g, mat.At(i, j))
			if err != nil {
				return nil, err
			}
			res.Set(i, j, x)
		}
	}

	return res, nil
}
