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
