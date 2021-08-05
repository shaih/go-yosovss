//
// Created by Fabrice Benhamouda on 8/4/21.
//

#ifndef VSS_PARITY_H
#define VSS_PARITY_H

#include <cstdint>
#include "algebra.hpp"

/**
 * Compute the parity-check matrix for the Shamir secret sharing
 * with reconstruction threshold t (i.e., degree = t-1)
 * and evaluation points 1,...,n
 *
 * Resulting matrix H has size (n+1) x (n+1-t)
 * A sharing sigma = (sigma_0,...,sigma_n)
 * (where sigma_0 is the secrete)
 * is valid iff sigma * H = 0
 * WARNING: This is the transpose of the code in cpp-lwevss
 *
 * Requires initNTL() to be called beforehand
 * to set up the modulo for NTL
 *
 * @param n number of evaluation points
 * @param t reconstruction threshold
 * @return parity-check matrix
 */
ALGEBRA::SMatrix computeParityMatrix(int n, int t);

/**
 * Function to be called before any other operation
 * used to set up the NTL modulo
 *
 * WARNING: may not be thread-safe
 */
void initNTL();

#endif //VSS_PARITY_H
