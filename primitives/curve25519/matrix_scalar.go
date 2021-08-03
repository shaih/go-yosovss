package curve25519

func ScalarMatrixMul(mat1 *ScalarMatrix, mat2 *ScalarMatrix) (*ScalarMatrix, error) {
	err := MatricesMulCompatible(mat1, mat2)
	if err != nil {
		return nil, err
	}

	res := NewScalarMatrix(mat1.rows, mat2.columns)

	for i := 0; i < res.rows; i++ {
		for j := 0; j < res.columns; j++ {
			for k := 0; k < mat1.columns; k++ {
				var x Scalar
				x = MultScalar(mat1.At(i, k), mat2.At(k, j))
				x = AddScalar(res.At(i, j), x)
				res.Set(i, j, x)
			}
		}
	}

	return res, nil
}
