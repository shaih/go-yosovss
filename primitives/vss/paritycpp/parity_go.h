//
// Created by Fabrice Benhamouda on 8/4/21.
//
// File imported in Go by swig (parity_go.swigcxx)

#ifndef VSS_PARITY_GO_H
#define VSS_PARITY_GO_H

#include <cstdint>

/**
 * Same as \ref computeParityMatrix
 * but parity-check matrix is stored in out
 * and initNTL is called automatically
 *
 * WARNING: may not be thread-safe
 *
 * Used to make call from Go easier
 *
 * @param out array of size 32*n*t, encoding = row-major, little endian
 */
void computeParityMatrixBytes(uint8_t *out, int n, int t);

#endif //VSS_PARITY_GO_H
