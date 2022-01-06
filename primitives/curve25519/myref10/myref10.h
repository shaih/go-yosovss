//
// Created by Fabrice Benhamouda on 8/16/21.
//

#ifndef MYREF10_MYREF10_H
#define MYREF10_MYREF10_H

#include <stdint.h>

// WARNING: all the xy functions assumes that the points are on the curve
// If it's not the case, behaviour is undefined
// (except for the is_on_curve function)

// Furthermore way too much copy-pasting!

// WARNING: Very dirty naming as done very quickly before deadline

int
crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                          const unsigned char *p);
// compared to libsodium one, it does not do any check, so faster!

int
crypto_scalarmult_ed25519_xy(unsigned char *q, const unsigned char *n,
                             const unsigned char *p);

int
crypto_scalarmult_ed25519_base_h(unsigned char *q,
                                 const unsigned char *n);

int
crypto_scalarmult_ed25519_base_g(unsigned char *q,
                                 const unsigned char *n);

int
crypto_scalarmult_ed25519_base_g_xy(unsigned char *q,
                                    const unsigned char *n);

int
crypto_scalarmult_ed25519_base_h_xy(unsigned char *q,
                                    const unsigned char *n);

int
crypto_double_scalarmult_ed25519_base_gh(unsigned char *q,
                                         const unsigned char *ng,
                                         const unsigned char *nh);

int
crypto_double_scalarmult_ed25519_base_gh_xy(unsigned char *q,
                                            const unsigned char *ng,
                                            const unsigned char *nh);

int
crypto_ed25519_compressed_to_xy(unsigned char *xy,
                                const unsigned char *compressed);

int
crypto_ed25519_xy_to_compressed(unsigned char *compressed,
                                const unsigned char *xy);

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
 * Sum all the points in p and store the result in r
 * @param r result array of 32 bytes
 * @param p array of 32*nb bytes, points are one after the other
 * @param nb
 * @return 0 if successful
 */
int
crypto_ed25519_add_points_xy(unsigned char *r, unsigned char *p, int nb);

/**
 * Sum all the points in p and store the result in r
 * AND check if the points are on the curve
 * @param r result array of 32 bytes
 * @param p array of 32*nb bytes, points are one after the other
 * @param nb
 * @return 0 if successful
 */
int
crypto_ed25519_add_points_check_on_curve_xy(unsigned char *r, unsigned char *p, int nb);

int
crypto_ed25519_add_xy(unsigned char *r, unsigned char *p, unsigned char *q);

int
crypto_ed25519_sub_xy(unsigned char *r, unsigned char *p, unsigned char *q);

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

/**
 * Generate a random scalar from a chacha20 key and nonce
 * Much faster than crypto_core_ed25519_scalar_random because faster randomness generator
 * @param s
 * @param chacha_key 32 bytes
 * @param chacha_nonce 8 bytes
 */
void
crypto_core_ed25519_scalar_random_chacha20(unsigned char *s, unsigned char *chacha_key, uint64_t chacha_nonce);

int
crypto_core_ed25519_is_on_curve(unsigned char *xy);

/**
 * Compute matrix a*b
 * @param c result matrix (n x l)
 * @param a first (n x m) matrix written in row-major
 * @param b second (m x l) matrix in row-major
 */
void
crypto_core_ed25519_scalar_matrix_mul(unsigned char *c, unsigned char *a, unsigned char *b, int n, int m, int l);

/**
 * Multi-point multiplication
 * @param q result in xy format (64 bytes)
 * @param a scalars, array of 32*n bytes, scalars are one after the others (msb < 127)
 * @param p array of 64*n bytes, points are one after the others in xy format
 * @param n number of points/scalars
 */
void
crypto_multi_scalarmult_ed25519_xy(unsigned char *q, const unsigned char *a,
                                   const unsigned char *p, int n);

/**
 * Same as crypto_multi_scalarmult_ed25519_xy but not constant time
 */
void
crypto_multi_scalarmult_ed25519_vartime_xy(unsigned char *q, const unsigned char *a,
                                           const unsigned char *p, int n);

#endif //MYREF10_MYREF10_H
