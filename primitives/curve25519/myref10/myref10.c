//
// Created by Fabrice Benhamouda on 8/16/21.
//

#include <sodium/crypto_stream_chacha20.h>
#include <sodium/crypto_core_ed25519.h>
#include "private/ed25519_ref10.h"
#include "myref10.h"


void
ge25519_scalarmult_base_h(ge25519_p3 *h, const unsigned char *a);

void
ge25519_double_scalarmult_base_gh(ge25519_p3 *h, const unsigned char *a, const unsigned char *b);

void
ge25519_madd(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q);

void
ge25519_msub(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q);

int
crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                          const unsigned char *p) {
    unsigned char *t = q;
    ge25519_p3 Q;
    ge25519_p3 P;

    unsigned int i;

    ge25519_frombytes(&P, p);

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;

    ge25519_scalarmult(&Q, t, &P);
    ge25519_p3_tobytes(q, &Q);
    return 0;
}

int
crypto_scalarmult_ed25519_xy(unsigned char *q, const unsigned char *n,
                             const unsigned char *p) {
    unsigned char *t = q;
    ge25519_p3 Q;
    ge25519_xy Q_xy;
    ge25519_p3 P;
    ge25519_xy P_xy;

    unsigned int i;

    ge25519_xy_fromxybytes(&P_xy, p);
    ge25519_xy_to_p3(&P, &P_xy);

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;

    ge25519_scalarmult(&Q, t, &P);
    ge25519_p3_to_xy(&Q_xy, &Q);
    ge25519_xy_toxybytes(q, &Q_xy);
    return 0;
}

// From https://github.com/jedisct1/libsodium/blob/6d566070b48efd2fa099bbe9822914455150aba9/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c
int crypto_scalarmult_ed25519_base_h(unsigned char *q, const unsigned char *n) {
    unsigned char *t = q;
    ge25519_p3 Q;
    unsigned int i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;

    ge25519_scalarmult_base_h(&Q, t);
    ge25519_p3_tobytes(q, &Q);
    return 0;
}

int crypto_scalarmult_ed25519_base_g(unsigned char *q, const unsigned char *n) {
    unsigned char *t = q;
    ge25519_p3 Q;
    unsigned int i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;

    ge25519_scalarmult_base(&Q, t);
    ge25519_p3_tobytes(q, &Q);
    return 0;
}

int crypto_scalarmult_ed25519_base_g_xy(unsigned char *q, const unsigned char *n) {
    unsigned char *t = q;
    ge25519_p3 Q;
    ge25519_xy Q_xy;
    unsigned int i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;

    ge25519_scalarmult_base(&Q, t);
    ge25519_p3_to_xy(&Q_xy, &Q);
    ge25519_xy_toxybytes(q, &Q_xy);
    return 0;
}

int crypto_scalarmult_ed25519_base_h_xy(unsigned char *q, const unsigned char *n) {
    unsigned char *t = q;
    ge25519_p3 Q;
    ge25519_xy Q_xy;
    unsigned int i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    t[31] &= 127;

    ge25519_scalarmult_base_h(&Q, t);
    ge25519_p3_to_xy(&Q_xy, &Q);
    ge25519_xy_toxybytes(q, &Q_xy);
    return 0;
}

int
crypto_double_scalarmult_ed25519_base_gh(unsigned char *q,
                                         const unsigned char *ng,
                                         const unsigned char *nh) {
    unsigned char *tg = q;
    unsigned char th[32];

    ge25519_p3 Q;
    unsigned int i;

    for (i = 0; i < 32; ++i) {
        tg[i] = ng[i];
        th[i] = nh[i];
    }
    tg[31] &= 127;
    th[31] &= 127;

    ge25519_double_scalarmult_base_gh(&Q, tg, th);
    ge25519_p3_tobytes(q, &Q);
    return 0;
}

int
crypto_double_scalarmult_ed25519_base_gh_xy(unsigned char *q,
                                            const unsigned char *ng,
                                            const unsigned char *nh) {
    unsigned char *tg = q;
    unsigned char th[32];

    ge25519_p3 Q;
    ge25519_xy Q_xy;
    unsigned int i;

    for (i = 0; i < 32; ++i) {
        tg[i] = ng[i];
        th[i] = nh[i];
    }
    tg[31] &= 127;
    th[31] &= 127;

    ge25519_double_scalarmult_base_gh(&Q, tg, th);
    ge25519_p3_to_xy(&Q_xy, &Q);
    ge25519_xy_toxybytes(q, &Q_xy);
    return 0;
}

int crypto_ed25519_add_points(unsigned char *r, unsigned char *p, int nb) {

    ge25519_p3 q_p3, r_p3;
    ge25519_p1p1 r_p1p1;
    ge25519_cached q_cached;

    if (nb <= 0) {
        return -1;
    }

    // load first value in r_p3
    if (ge25519_frombytes(&r_p3, p) != 0) {
        return -1;
    }

    for (int i = 1; i < nb; i++) {
        if (ge25519_frombytes(&q_p3, p + 32 * i) != 0) {
            return -1;
        }
        ge25519_p3_to_cached(&q_cached, &q_p3);
        ge25519_add(&r_p1p1, &r_p3, &q_cached);
        ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    }

    ge25519_p3_tobytes(r, &r_p3);

    return 0;
}

int
crypto_ed25519_add_points_xy(unsigned char *r, unsigned char *p, int nb) {
    ge25519_p3 r_p3;
    ge25519_p1p1 r_p1p1;
    ge25519_xy q_xy;
    ge25519_precomp q_precomp;

    if (nb <= 0) {
        return -1;
    }

    // load first value in r_p3
    ge25519_xy_fromxybytes(&q_xy, p + 0);
    ge25519_xy_to_p3(&r_p3, &q_xy);

    for (int i = 1; i < nb; i++) {
        ge25519_xy_fromxybytes(&q_xy, p + 64 * i);
        ge25519_xy_to_precomp(&q_precomp, &q_xy);
        ge25519_madd(&r_p1p1, &r_p3, &q_precomp);
        ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    }

    ge25519_p3_to_xy(&q_xy, &r_p3);
    ge25519_xy_toxybytes(r, &q_xy);

    return 0;
}


int
crypto_ed25519_add_points_check_on_curve_xy(unsigned char *r, unsigned char *p, int nb) {
    ge25519_p3 r_p3;
    ge25519_p1p1 r_p1p1;
    ge25519_xy q_xy;
    ge25519_precomp q_precomp;

    if (nb <= 0) {
        return -1;
    }

    // load first value in r_p3
    ge25519_xy_fromxybytes(&q_xy, p + 0);
    if (ge25519_xy_is_on_curve(&q_xy) == 0) {
        return -1;
    }
    ge25519_xy_to_p3(&r_p3, &q_xy);

    for (int i = 1; i < nb; i++) {
        ge25519_xy_fromxybytes(&q_xy, p + 64 * i);
        if (ge25519_xy_is_on_curve(&q_xy) == 0) {
            return -1;
        }
        ge25519_xy_to_precomp(&q_precomp, &q_xy);
        ge25519_madd(&r_p1p1, &r_p3, &q_precomp);
        ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    }

    ge25519_p3_to_xy(&q_xy, &r_p3);
    ge25519_xy_toxybytes(r, &q_xy);

    return 0;
}

int
crypto_ed25519_add_xy(unsigned char *r, unsigned char *p, unsigned char *q) {
    ge25519_xy q_xy;
    ge25519_precomp q_precomp;
    ge25519_p1p1 r_p1p1;
    ge25519_p3 r_p3;

    ge25519_xy_fromxybytes(&q_xy, p);
    ge25519_xy_to_p3(&r_p3, &q_xy); // maybe sub-optimal: couldn't we have a better formular with 2 precomp?
    ge25519_xy_fromxybytes(&q_xy, q);
    ge25519_xy_to_precomp(&q_precomp, &q_xy);

    ge25519_madd(&r_p1p1, &r_p3, &q_precomp);
    ge25519_p1p1_to_p3(&r_p3, &r_p1p1);

    ge25519_p3_to_xy(&q_xy, &r_p3);
    ge25519_xy_toxybytes(r, &q_xy);

    return 0;
}

int
crypto_ed25519_sub_xy(unsigned char *r, unsigned char *p, unsigned char *q) {
    ge25519_xy q_xy;
    ge25519_precomp q_precomp;
    ge25519_p1p1 r_p1p1;
    ge25519_p3 r_p3;

    ge25519_xy_fromxybytes(&q_xy, p);
    ge25519_xy_to_p3(&r_p3, &q_xy); // maybe sub-optimal: couldn't we have a better formula with 2 precomp?
    ge25519_xy_fromxybytes(&q_xy, q);
    ge25519_xy_to_precomp(&q_precomp, &q_xy);

    ge25519_msub(&r_p1p1, &r_p3, &q_precomp);
    ge25519_p1p1_to_p3(&r_p3, &r_p1p1);

    ge25519_p3_to_xy(&q_xy, &r_p3);
    ge25519_xy_toxybytes(r, &q_xy);

    return 0;
}

void crypto_ed25519_muladd_scalar(unsigned char *r, unsigned char *a, unsigned char *b, unsigned char *c) {
    sc25519_muladd(r, a, b, c);
}

void crypto_ed25519_polynomial_evaluation(unsigned char *r, unsigned char *poly, int degree, unsigned char *x) {
    // Horner evaluation

    memcpy(r, &poly[degree * 32], 32);
    for (int i = degree - 1; i >= 0; i--) {
        sc25519_muladd(r, r, x, &poly[i * 32]);
    }
}

void crypto_core_ed25519_scalar_random_chacha20(unsigned char *s, unsigned char *chacha_key, uint64_t chacha_nonce) {
    // From crypto_core_ed25519_scalar_random

    // The full nonce is the concatenation of the nonce in argument
    // and of a 32-bit counter_nonce
    unsigned char full_nonce[12];
    uint32_t counter_nonce = 0;
    memcpy(full_nonce, &chacha_nonce, sizeof chacha_nonce);

    do {
        counter_nonce++;
        memcpy(&full_nonce[8], &counter_nonce, sizeof counter_nonce);
        crypto_stream_chacha20_ietf(s, 32, full_nonce, chacha_key);
        s[crypto_core_ed25519_SCALARBYTES - 1] &= 0x1f;
    } while (sc25519_is_canonical(s) == 0 ||
             sodium_is_zero(s, crypto_core_ed25519_SCALARBYTES));
}

int
crypto_ed25519_compressed_to_xy(unsigned char *xy,
                                const unsigned char *compressed) {
    // WARNING: NOT OPTIMZED

    ge25519_p3 p_p3;
    ge25519_xy p_xy;

    if (ge25519_frombytes(&p_p3, compressed) != 0) {
        return -1;
    }

    ge25519_p3_to_xy(&p_xy, &p_p3);
    ge25519_xy_toxybytes(xy, &p_xy);

    return 0;
}

int
crypto_core_ed25519_is_on_curve(unsigned char *xy) {
    ge25519_xy p_xy;
    ge25519_xy_fromxybytes(&p_xy, xy);
    return ge25519_xy_is_on_curve(&p_xy);
}

// return the coordinate for row-major of (i,j) for a matrix with m columns
// of scalars
inline int sc_row_major_coord(int i, int j, int m) {
    return (i * m + j) * 32;
}

void crypto_core_ed25519_scalar_matrix_mul(unsigned char *c,
                                           unsigned char *a,
                                           unsigned char *b,
                                           int n, int m, int l) {

    for (int i = 0; i < n; i++) {
        for (int k = 0; k < l; k++) {
            sc25519_mul(
                    c + sc_row_major_coord(i, k, l),
                    a + sc_row_major_coord(i, 0, m),
                    b + sc_row_major_coord(0, k, l)
            );

            for (int j = 1; j < m; j++) {
                sc25519_muladd(
                        c + sc_row_major_coord(i, k, l),
                        a + sc_row_major_coord(i, j, m),
                        b + sc_row_major_coord(j, k, l),
                        c + sc_row_major_coord(i, k, l)
                );
            }
        }
    }

}
