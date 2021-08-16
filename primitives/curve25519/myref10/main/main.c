#include <stdio.h>
#include <assert.h>

#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        printf("ERROR: sodium cannot be initialized\n");
        return -1;
    }

    printf("Generating the point H for Pedersen:\n");

    // It is the hash of an arbitrary message then converted to a point
    assert(crypto_generichash_BYTES == 32);
    assert(crypto_core_ed25519_UNIFORMBYTES == 32);
    unsigned char MESSAGE[] = "YOSO Pedersen H...";
    // we chose a string until we got a high-bit of the point equal to 0
    // looks like otherwise we have weird issues...
    // my guess is that the Python script only supports high-bit = 0, as high-bit encodes the X coord
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof hash,
                       MESSAGE, sizeof MESSAGE,
                       NULL, 0);

    unsigned char hx[crypto_core_ed25519_BYTES];
    crypto_core_ed25519_from_uniform(hx, hash);



    unsigned char hx_big_endian[crypto_core_ed25519_BYTES];
    for(int i = 0; i < crypto_core_ed25519_BYTES; i++) {
        hx_big_endian[i] = hx[crypto_core_ed25519_BYTES-i-1];
    }

    char hx_hex[2*crypto_core_ed25519_BYTES+1];
    sodium_bin2hex(hx_hex, sizeof hx_hex, hx_big_endian, sizeof hx_big_endian);

    printf("%s", hx_hex);

    return 0;
}
