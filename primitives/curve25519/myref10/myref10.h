//
// Created by Fabrice Benhamouda on 8/16/21.
//

#ifndef MYREF10_MYREF10_H
#define MYREF10_MYREF10_H

int
crypto_scalarmult_ed25519_base_h(unsigned char *q,
                                 const unsigned char *n);

int
crypto_scalarmult_ed25519_base_g(unsigned char *q,
                                 const unsigned char *n);

int
crypto_double_scalarmult_ed25519_base_gh(unsigned char *q,
                                         const unsigned char *ng,
                                         const unsigned char *nh);

/**
 * Sum all the points in p and store the result in r
 * @param r result array of 32 bytes
 * @param p array of 32*nb bytes, points are one after the other
 * @param nb
 * @return 0 if successful
 */
int
crypto_ed25519_add_points(unsigned char *r, unsigned char *p, int nb);

/**
 *
 * @param r result ab + c
 * @param a
 * @param b
 * @param c
 */
void
crypto_ed25519_muladd_scalar(unsigned char *r, unsigned char *a, unsigned char *b, unsigned char *c);

/**
 *
 * @param r result poly(x)
 * @param poly as coefficients u_0, ..., u_degree where u_0 is the constant coefficient
 * @param degree
 * @param x
 */
void
crypto_ed25519_polynomial_evaluation(unsigned char *r, unsigned char *poly, int degree, unsigned char *c);

#endif //MYREF10_MYREF10_H
