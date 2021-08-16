//
// Created by Fabrice Benhamouda on 8/16/21.
//

#include "private/ed25519_ref10.h"

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
