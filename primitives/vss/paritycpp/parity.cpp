#include "parity_go.h"
#include "parity.h"
#include <cstdint>
#include <iostream>
#include "algebra.hpp"

using namespace ALGEBRA;

SMatrix computeParityMatrix(int n, int t) {
    const int nHcols = n+1; // number of columns in H

    // Set the generating matrix G, and then H is its kernel. The columns
    // of G span the space of valid sharings at the evaluation points
    // (0, i_1, i_2, ..., i_n): The j'th column is the evaluation of
    // the polynomial p(X)=X^j at all these points.
    SMatrix G;
    resize(G, nHcols, t);

    // The first columns of G is an all-1 column
    for (int i=0; i<nHcols; i++) {
        conv(G[i][0], 1);
    }

    // The j'th column euqals the j-1'st one times the evaluation points
    for (int j=1; j<t; j++) {
        for (int i=1; i<=n; i++) { // row 0 need not change
            G[i][j] = G[i][j-1] * i;
        }
    }

    SMatrix H;
    kernel(H,G); // compute H

    return transpose(H);
}

void initNTL() {
    // Initialize the NTL global modulus to 2^{252} +27742...493
    auto Pmod = (toBigInt(1) << 252)
                + NTL::conv<NTL::ZZ>("27742317777372353535851937790883648493");
    NTL::ZZ_p::init(Pmod);
}