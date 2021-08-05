//
// Created by Fabrice Benhamouda on 8/4/21.
//

#include <iostream>
#include <cstdint>

#include "parity.h"
#include "parity_go.h"


using namespace ALGEBRA;

void encodeSMatrixToBytes(uint8_t *out, SMatrix &in) {
    for (int i = 0; i < in.NumRows(); i++) {
        for (int j = 0; j < in.NumCols(); j++) {
            scalarBytes(&out[(i * in.NumCols() + j) * 32], in[i][j], 32);
        }
    }
}

void computeParityMatrixBytes(uint8_t *out, int n, int t) {
    initNTL();
    SMatrix H;
    H = computeParityMatrix(n, t);
    encodeSMatrixToBytes(out, H);
}

