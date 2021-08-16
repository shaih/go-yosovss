//
// Created by Fabrice Benhamouda on 8/16/21.
//

#include "private/ed25519_ref10.h"
#include "myref10.h"


void
ge25519_scalarmult_base_h(ge25519_p3 *h, const unsigned char *a);


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
