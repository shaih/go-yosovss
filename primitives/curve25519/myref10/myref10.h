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

/**
 * Sum all the points in p and store the result in r
 * @param r result array of 32 bytes
 * @param p array of 32*nb bytes, points are one after the other
 * @param nb
 * @return the sum of all the points
 */
int
crypto_ed25519_add_points(unsigned char *r, unsigned char *p, int nb);

#endif //MYREF10_MYREF10_H
